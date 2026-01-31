import networkx as nx
import json
import re
import os
from pathlib import Path
from typing import List, Dict, Set, Optional

# ----------------------------
# Cache helpers
# ----------------------------
CACHE_ROOT = Path(".flow_cache")

def cache_dir(project_path: str) -> Path:
    d = CACHE_ROOT / Path(project_path).name
    d.mkdir(parents=True, exist_ok=True)
    return d

def load_cache(project_path: str):
    d = cache_dir(project_path)
    cache_file = d / "cache.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding='utf-8'))
        except:
            return None
    return None

def save_cache(project_path: str, facts, flows):
    d = cache_dir(project_path)
    data = {"facts": facts, "flows": flows}
    (d / "cache.json").write_text(json.dumps(data, indent=2), encoding='utf-8')

# --- CONFIGURATION ---
IGNORE_EXTENSIONS = {
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', 
    '.ico', '.woff', '.woff2', '.ttf', '.svg'
}

# Prefixes in Controller Methods that imply state change (Action)
ACTION_PREFIXES = ('delete', 'remove', 'update', 'save', 'create', 'add', 'process', 'do', 'submit', 'post', 'edit')

# ----------------------------
# Context Path Detection
# ----------------------------
def determine_context_path(project_path: str) -> str:
    """
    Auto-detects the Web Context Path by scanning build files.
    """
    root_path = Path(project_path)
    
    # 1. Check Spring Boot properties
    props_file = root_path / "src" / "main" / "resources" / "application.properties"
    if props_file.exists():
        try:
            content = props_file.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r'server\.servlet\.context-path\s*=\s*([^\s]+)', content)
            if match:
                return match.group(1).strip()
        except:
            pass

    # 2. Check Maven pom.xml
    pom_file = root_path / "pom.xml"
    if pom_file.exists():
        try:
            content = pom_file.read_text(encoding="utf-8", errors="ignore")
            match = re.search(r'<finalName>([^<]+)</finalName>', content)
            if match:
                war_name = match.group(1).strip()
                if "${" not in war_name:
                    return f"/{war_name}"
        except:
            pass

    # 3. Fallback: Use Directory Name
    return f"/{root_path.name}"

# ----------------------------
# Helper: URL Base Path
# ----------------------------
def get_url_base_path(full_url: str) -> str:
    if not full_url: return ""
    clean = full_url.strip("/")
    parts = clean.split("/")
    if len(parts) > 0:
        return "/".join(parts[:-1])
    return ""

# ----------------------------
# JSP Scraper
# ----------------------------
def scan_jsp_for_links(file_path: Path, context_path: str) -> List[Dict]:
    results = []
    try:
        if not file_path.exists(): return []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        
        # 1. SPRING FORMS (<form:form>)
        spring_matches = re.findall(r'<form:form\s+[^>]*action=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for raw in spring_matches:
            clean = _clean_link(raw, context_path)
            if clean: results.append({"target": clean, "type": "form"})

        # 2. HTML FORMS (<form>)
        raw_forms = re.findall(r'<form\s+([^>]+)>', content, re.IGNORECASE)
        for attrs in raw_forms:
            action_match = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if action_match:
                clean = _clean_link(action_match.group(1), context_path)
                if clean: results.append({"target": clean, "type": "form"})

        # 3. LINKS & JSTL
        jstl_matches = re.findall(r'<c:url\s+value=["\']([^"\']+)["\']', content, re.IGNORECASE)
        html_matches = re.findall(r'href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        js_matches = re.findall(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        
        raw_links = jstl_matches + html_matches + js_matches

        for raw in raw_links:
            clean = _clean_link(raw, context_path)
            if clean: results.append({"target": clean, "type": "link"})

    except Exception as e:
        print(f"[Warn] Could not parse JSP {file_path.name}: {e}")
    return results

def _clean_link(raw_link: str, context_path: str) -> Optional[str]:
    clean = raw_link.strip()
    if clean.startswith("<c:url") or clean.startswith(('javascript:', '#', 'mailto:')) or len(clean) == 0: 
        return None

    # Strip Context Path
    if context_path != "/" and clean.startswith(context_path):
        clean = clean[len(context_path):]
    elif clean.startswith(f"{context_path}/"): 
        clean = clean[len(context_path):]

    # Strip EL Expressions
    clean = re.sub(r'^\$\{.*\}', '', clean) 
    
    # Filter Static Assets
    _, ext = os.path.splitext(clean)
    if ext.lower() in IGNORE_EXTENSIONS:
        return None
            
    if clean.startswith("/"):
        clean = clean[1:]
    return clean

# ----------------------------
# MAIN: Build Graph
# ----------------------------
def build_graph(facts: List[Dict], project_path: str):
    print(f"build_graph--> Building graph for project at: {project_path}")
    G = nx.DiGraph()
    root_path = Path(project_path)
    print(f"build_graph--> Scanning root path: {root_path}")
    context_path = determine_context_path(project_path)
    print(f"build_graph--> Detected Context Path: '{context_path}'")
    url_to_node = {} 

    # --- PASS 1: Create Nodes & Index URLs ---
    for item in facts:
        cls = item["class"]
        method = item["method"]
        node_id = f"{cls}.{method}"
        type_ = item.get("type", "UNKNOWN")
        
        if cls not in G:
            G.add_node(cls, type="class", label=cls, layer=type_)
        
        display_layer = type_ if type_ in ["CONTROLLER", "SERVICE", "DAO"] else "method"
        
        # [CRITICAL UPDATE]: The 'item' dict now contains 'dependencies' from ParseSpring.java
        # We store the entire 'item' as details, so G.nodes[id]['details']['dependencies'] is available.
        G.add_node(node_id, 
                   type="method", 
                   layer=display_layer, 
                   label=method, 
                   details=item) 
                   
        G.add_edge(cls, node_id, label="declares")

        if item.get("url"):
            raw_url = item["url"]
            clean_url = raw_url.strip("/")
            url_to_node[clean_url] = node_id
            if raw_url.startswith("/"):
                url_to_node[raw_url] = node_id 

    # --- PASS 2: Add Java & View Edges ---
    for item in facts:
        src_id = f"{item['class']}.{item['method']}"
        
        # Java Calls (Service/DAO calls)
        for dc in item.get("downstream_calls", []):
            target_class = dc.get("class")
            target_method = dc.get("method")
            if target_class and target_method:
                tgt_id = f"{target_class}.{target_method}"
                if tgt_id not in G:
                    G.add_node(tgt_id, type="method", layer="method", label=target_method, 
                               details={"class": target_class, "method": target_method})
                G.add_edge(src_id, tgt_id, label="calls")

        # View Renders
        if item.get("type") == "CONTROLLER" and item.get("ui_view"):
            view_str = item["ui_view"]
            target_url = view_str.replace("redirect:", "").replace("forward:", "").strip()
            
            # Handle Context Path stripping
            if context_path != "/" and target_url.startswith(context_path):
                target_url = target_url[len(context_path):]
            
            lookup_key = target_url.strip("/")

            if view_str.startswith("redirect:"):
                if lookup_key in url_to_node:
                    G.add_edge(src_id, url_to_node[lookup_key], label="redirects")
                else:
                    if target_url not in G: G.add_node(target_url, type="UI", layer="URL", label=target_url)
                    G.add_edge(src_id, target_url, label="redirects")
            
            elif view_str.startswith("forward:"):
                if lookup_key in url_to_node:
                    G.add_edge(src_id, url_to_node[lookup_key], label="forwards")
                else:
                    if target_url not in G: G.add_node(target_url, type="UI", layer="URL", label=target_url)
                    G.add_edge(src_id, target_url, label="forwards")
            
            else: # Standard JSP Render
                jsp_name = view_str
                if jsp_name not in G:
                    G.add_node(jsp_name, type="UI", layer="UI", label=jsp_name, details={"file": jsp_name + ".jsp"})
                G.add_edge(src_id, jsp_name, label="renders")

    # --- INTERMEDIATE: Identify JSP Owners (for Relative URL resolution) ---
    jsp_owners = {}
    for src, tgt, data in G.edges(data=True):
        if data.get("label") == "renders":
            if tgt not in jsp_owners: jsp_owners[tgt] = []
            owner_details = G.nodes[src].get("details", {})
            jsp_owners[tgt].append({"id": src, "url": owner_details.get("url", "")})

    # --- PASS 3: Scan Physical JSPs ---
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if file.endswith(".jsp"):
                name_no_ext = file[:-4]
                full_path = Path(root) / file
                
                if name_no_ext not in G:
                    G.add_node(name_no_ext, type="UI", layer="UI", label=name_no_ext, details={"file": str(full_path), "type": "UI"})
                else:
                    G.nodes[name_no_ext]['details'] = {"file": str(full_path), "type": "UI"}

                actions = scan_jsp_for_links(full_path, context_path)
                
                for action in actions:
                    link_clean = action["target"]
                    tag_type = action["type"]
                    target_node_id = None

                    # A. Relative Resolution
                    if name_no_ext in jsp_owners:
                        for owner in jsp_owners[name_no_ext]:
                            owner_url = owner["url"]
                            if owner_url:
                                base_path = get_url_base_path(owner_url)
                                candidate = f"{base_path}/{link_clean}".strip("/")
                                if candidate in url_to_node:
                                    target_node_id = url_to_node[candidate]
                                    break
                    
                    # B. Global Resolution
                    if not target_node_id and link_clean in url_to_node:
                        target_node_id = url_to_node[link_clean]
                    
                    if target_node_id:
                        edge_label = "submits_data" if tag_type == "form" else "navigates_to"
                        if tag_type == "link":
                             # If link target is an action method, treat as trigger
                            target_lbl = G.nodes[target_node_id].get("label", "").lower()
                            if target_lbl.startswith(ACTION_PREFIXES): edge_label = "triggers_action"
                        
                        G.add_edge(name_no_ext, target_node_id, label=edge_label)
                    else:
                        # Link to external or unmapped URL
                        if len(link_clean) > 1:
                            display = "/" + link_clean
                            if display not in G: G.add_node(display, type="UI", layer="URL", label=display)
                            G.add_edge(name_no_ext, display, label="navigates_to")

    return G

# ----------------------------
# Detect Flows
# ----------------------------
def detect_flows(G: nx.DiGraph):
    flows = {}
    controller_methods = [n for n, d in G.nodes(data=True) if d.get("layer") == "CONTROLLER"]

    for ctrl_method in controller_methods:
        clean_name = ctrl_method.replace('.', '_')
        flow_name = f"Flow_{clean_name}"
        visited = set()
        stack = [ctrl_method]
        flow_order = []
        VALID_EDGES = {"calls", "renders", "redirects", "forwards", "submits_data", "triggers_action"}

        while stack:
            node = stack.pop()
            if node in visited: continue
            visited.add(node)
            flow_order.append(node)
            
            successors = []
            for succ in G.successors(node):
                if G.edges[node, succ].get("label") in VALID_EDGES:
                    successors.append(succ)
            stack.extend(reversed(successors))

        if len(flow_order) > 1:
            flows[flow_name] = flow_order
            for node in flow_order:
                G.nodes[node]["flow"] = flow_name

    return flows

def initialize_migration_inventory(facts, project_path):

    routes = {}
    for fact in facts:
        # We only care about Controllers that have a URL mapping
        if fact.get("type") == "CONTROLLER" and fact.get("url"):
            legacy_url = fact["url"]
            
            # Don't overwrite if it exists (preserve status)
            if legacy_url not in routes:
                routes[legacy_url] = {
                    "id": f"{fact['class']}.{fact['method']}",
                    "type": "CONTROLLER",
                    "status": "PENDING",
                    "legacy_file": os.path.basename(fact['file']),
                    "legacy_url": legacy_url,
                    "ui_view": fact.get("ui_view"),
                    "new_react_route": None,
                    "new_api_endpoint": None
                }

    # Save to disk
    full_data = {
        "summary": {
            "total_endpoints": len(routes),
            "migrated": sum(1 for r in routes.values() if r["status"] == "MIGRATED"),
            "pending": sum(1 for r in routes.values() if r["status"] == "PENDING")
        },
        "routes": routes
    }

    #with open(inventory_path, 'w') as f:
    #    json.dump(full_data, f, indent=2)
    
    return full_data

# ----------------------------
# View Helpers
# ----------------------------
def build_flow_execution_table(G: nx.DiGraph, flows: Dict):
    table = {}
    for flow_name, nodes in flows.items():
        subG = G.subgraph(nodes).copy()
        try: linear_order = list(nx.topological_sort(subG))
        except: linear_order = list(nx.dfs_preorder_nodes(subG))

        ordered_nodes = []
        for n in linear_order:
            node_data = G.nodes[n]
            details = node_data.get("details", {})
            ordered_nodes.append({
                "node": n,
                "type": node_data.get("layer", "UNKNOWN"), 
                "file": details.get("file", ""),
                "flow": flow_name
            })
        table[flow_name] = ordered_nodes
    return table

def expand_dependencies(G, method_nodes, depth=2):
    expanded = set(method_nodes)
    current_layer = list(method_nodes)
    
    # Add parents of initial methods
    for n in method_nodes:
        if "." in n: expanded.add(n.rsplit(".", 1)[0])

    for _ in range(depth):
        next_layer = []
        for n in current_layer:
            for succ in G.successors(n):
                if G.edges[n, succ].get("label") == "calls":
                    expanded.add(succ)
                    next_layer.append(succ)
                    if "." in succ: expanded.add(succ.rsplit(".", 1)[0])
        current_layer = next_layer
    return expanded

def get_jsp_centric_view(G: nx.DiGraph, jsp_name: str):
    if jsp_name not in G: return nx.DiGraph()
    relevant = {jsp_name}
    methods = set()
    
    # Inbound (Rendering Controllers)
    for pred in G.predecessors(jsp_name):
        if G.edges[pred, jsp_name].get("label") in ["renders", "redirects", "forwards"]:
            relevant.add(pred)
            methods.add(pred)

    # Outbound (Actions)
    for succ in G.successors(jsp_name):
        relevant.add(succ)
        methods.add(succ)
    
    relevant.update(expand_dependencies(G, methods))
    return G.subgraph(relevant).copy()

def get_controller_centric_view(G: nx.DiGraph, class_name: str):
    if class_name not in G: return nx.DiGraph()
    relevant = {class_name}
    methods = [n for n in G.successors(class_name) if G.edges[class_name, n].get("label") == "declares"]
    relevant.update(methods)
    
    # Outputs (JSPs/Redirects)
    for m in methods:
        for succ in G.successors(m):
            if G.edges[m, succ].get("label") in ["renders", "redirects", "forwards"]:
                relevant.add(succ)

    # Inputs (JSPs calling these methods)
    for m in methods:
        for pred in G.predecessors(m):
            if G.edges[pred, m].get("label") in ["submits_data", "triggers_action", "navigates_to"]:
                relevant.add(pred)

    relevant.update(expand_dependencies(G, methods))
    return G.subgraph(relevant).copy()

def nx_to_reactflow(G):
    nodes = []
    edges = []
    for n, d in G.nodes(data=True):
        nodes.append({
            "id": n,
            "type": "default",
            "data": {"label": d.get("label", n), "details": d.get("details", {}), "layer": d.get("layer","")},
            "position": {"x": 0, "y": 0}
        })
    for u, v, d in G.edges(data=True):
        edges.append({
            "id": f"{u}-{v}",
            "source": u,
            "target": v,
            "label": d.get("label", "")
        })
    return {"nodes": nodes, "edges": edges}