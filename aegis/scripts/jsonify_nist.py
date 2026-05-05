import json
import os

def create_lean_map():
    catalog_path = "intel/compliance/NIST_SP-800-53_rev5_catalog.json"
    output_path = "intel/compliance/compliance_map.json"
    
    if not os.path.exists(catalog_path):
        print(f"❌ Catalog not found at {catalog_path}")
        return

    with open(catalog_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    lean_map = {}
    
    # We navigate the NIST OSCAL structure to pull the control descriptions
    # Groups -> Controls -> Params/Parts
    for group in data.get('catalog', {}).get('groups', []):
        group_id = group.get('id', '').upper()
        if group_id in ['AU', 'SI', 'AC', 'IA']:
            for control in group.get('controls', []):
                control_id = control.get('id', '').upper()
                title = control.get('title', '')
                
                # Extracting the requirement text
                parts = control.get('parts', [])
                statement = ""
                for part in parts:
                    if part.get('name') == 'statement':
                        for subpart in part.get('parts', []):
                            statement += subpart.get('prose', '') + " "
                
                lean_map[control_id] = {
                    "title": title,
                    "requirement": statement.strip()
                }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(lean_map, f, indent=2)
    
    print(f"Lean Compliance Map created: {output_path} ({len(lean_map)} controls mapped)")

if __name__ == "__main__":
    create_lean_map()
