import requests
import json
import os
import yaml
import sys
import time

# --- CONFIGURATION ---
REPO_OWNER = "splunk"
REPO_NAME = "attack_data"
OUTPUT_FILE = "logs/bots_dataset/cloud_curated.json"
SIZE_LIMIT = 75 * 1024 * 1024  # 75MB target

# DISCOVERED SEEDS (105 Unique Cloud YAMLS)
SEED_YAMLS = ["datasets/attack_techniques/T1078.004/aws_keyspace_list_keys_discovery/aws_keyspace_list_keys_discovery_old.yml", "datasets/attack_techniques/T1078.004/aws_saml_update_identity_provider/aws_saml_update_identity_provider_old.yml", "datasets/attack_techniques/T1078/aws_createaccesskey/aws_createaccesskey.yml", "datasets/attack_techniques/T1087.004/aws_invoke_model_access_denied/aws_invoke_model_access_denied_old.yml", "datasets/attack_techniques/T1090.003/aws_cloudtrail_proxy_detection/aws_cloudtrail_proxy_detection_old.yml", "datasets/attack_techniques/T1098.001/aws_iam_access_key_deleted/aws_iam_access_key_deleted_old.yml", "datasets/attack_techniques/T1098.002/o365_exchange_mailbox_policy_changed/o365_exchange_mailbox_policy_changed.yml", "datasets/attack_techniques/T1098.003/azure_ad_high_priv_role_assigned/azure_ad_high_priv_role_assigned.yml", "datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.yml", "datasets/attack_techniques/T1098.003/azure_ad_spn_privesc/azure_ad_spn_privesc.yml", "datasets/attack_techniques/T1098.003/o365_admin_consent/o365_admin_consent.yml", "datasets/attack_techniques/T1098.003/o365_bypass_admin_consent/o365_bypass_admin_consent.yml", "datasets/attack_techniques/T1098.003/o365_grant_mail_read/o365_grant_mail_read.yml", "datasets/attack_techniques/T1098.003/o365_high_priv_role_assigned/o365_high_priv_role_assigned.yml", "datasets/attack_techniques/T1098.003/o365_privileged_graph_perm_assigned/o365_privileged_graph_perm_assigned.yml", "datasets/attack_techniques/T1098.003/o365_spn_privesc/o365_spn_privesc.yml", "datasets/attack_techniques/T1098/aws_iam_failure_group_deletion/data.yml", "datasets/attack_techniques/T1098/aws_iam_successful_group_deletion/data.yml", "datasets/attack_techniques/T1098/azure_ad_add_serviceprincipal_owner/azure_ad_add_serviceprincipal_owner.yml", "datasets/attack_techniques/T1098/azure_ad_set_immutableid/azure_ad_set_immutableid.yml", "datasets/attack_techniques/T1098/o365_add_app_registration_owner/o365_add_app_registration_owner.yml", "datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.yml", "datasets/attack_techniques/T1110.001/o365_high_number_authentications_for_user/o365_high_number_authentications_for_user.yml", "datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_rds_password_reset.yml", "datasets/attack_techniques/T1110.003/o365_distributed_spray/o365_distributed_spray.yml", "datasets/attack_techniques/T1110.003/o365_multiple_users_from_ip/o365_multiple_users_from_ip.yml", "datasets/attack_techniques/T1110/azure_mfasweep_events/azure_mfasweep_events.yml", "datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.yml", "datasets/attack_techniques/T1114.002/o365_compliance_content_search_exported/o365_compliance_content_search_exported.yml", "datasets/attack_techniques/T1114.002/o365_compliance_content_search_started/o365_compliance_content_search_started.yml", "datasets/attack_techniques/T1114.002/o365_inbox_shared_with_all_users/o365_inbox_shared_with_all_users.yml", "datasets/attack_techniques/T1114.002/o365_multiple_mailboxes_accessed_via_api/o365_multiple_mailboxes_accessed_via_api.yml", "datasets/attack_techniques/T1114.002/o365_oauth_app_ews_mailbox_access/o365_oauth_app_ews_mailbox_access.yml", "datasets/attack_techniques/T1114.002/o365_oauth_app_graph_mailbox_access/o365_oauth_app_graph_mailbox_access.yml", "datasets/attack_techniques/T1114.002/suspicious_rights_delegation/suspicious_rights_delegation_old.yml", "datasets/attack_techniques/T1114.003/transport_rule_change/transport_rule_change_old.yml", "datasets/attack_techniques/T1114/o365_export_pst_file/o365_export_pst_file.yml", "datasets/attack_techniques/T1114/o365_new_forwarding_mailflow_rule_created/o365_new_forwarding_mailflow_rule_created.yml", "datasets/attack_techniques/T1119/aws_exfil_datasync/aws_exfil_datasync_old.yml", "datasets/attack_techniques/T1136.003/azure_ad_add_service_principal/azure_ad_add_service_principal.yml", "datasets/attack_techniques/T1136.003/azure_ad_multiple_service_principals_created/azure_ad_multiple_service_principals_created.yml", "datasets/attack_techniques/T1136.003/azure_automation_account/azure_automation_account.yml", "datasets/attack_techniques/T1136.003/o365_add_app_role_assignment_grant_user/o365_add_app_role_assignment_grant_user.yml", "datasets/attack_techniques/T1136.003/o365_add_service_principal/o365_add_service_principal.yml", "datasets/attack_techniques/T1136.003/o365_added_service_principal/o365_added_service_principal.yml", "datasets/attack_techniques/T1136.003/o365_multiple_service_principals_created/o365_multiple_service_principals_created.yml", "datasets/attack_techniques/T1136.003/o365_new_federated_domain/o365_new_federated_domain.yml", "datasets/attack_techniques/T1136.003/o365_new_federated_domain_added/o365_new_federated_domain_added.yml", "datasets/attack_techniques/T1136.003/o365_new_federation/o365_new_federation.yml", "datasets/attack_techniques/T1136/snapattack/snapattack.yml", "datasets/attack_techniques/T1185/azure_ad_concurrent_sessions_from_different_ips/azure_ad_concurrent_sessions_from_different_ips.yml", "datasets/attack_techniques/T1185/o365_concurrent_sessions_from_different_ips/o365_concurrent_sessions_from_different_ips.yml", "datasets/attack_techniques/T1201/aws_password_policy/aws_password_policy_old.yml", "datasets/attack_techniques/T1204/kube_audit_create_node_port_service/kube_audit_create_node_port_service_old.yml", "datasets/attack_techniques/T1213.002/o365_sus_sharepoint_search/o365_sus_sharepoint_search.yml", "datasets/attack_techniques/T1485/decommissioned_buckets/decommissioned_buckets.yml", "datasets/attack_techniques/T1486/s3_file_encryption/s3_file_encryption.yml", "datasets/attack_techniques/T1525/container_implant/container_implant_old.yml", "datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.yml", "datasets/attack_techniques/T1528/azure_ad_user_consent_granted/azure_ad_user_consent_granted.yml", "datasets/attack_techniques/T1528/device_code_authentication/device_code_authentication.yml", "datasets/attack_techniques/T1528/o365_user_consent_blocked/o365_user_consent_blocked.yml", "datasets/attack_techniques/T1528/o365_user_consent_declined/o365_user_consent_declined.yml", "datasets/attack_techniques/T1528/o365_user_consent_mail_permissions/o365_user_consent_mail_permissions.yml", "datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_s3_public_bucket.yml", "datasets/attack_techniques/T1537/aws_ami_shared_public/aws_ami_shared_public.yml", "datasets/attack_techniques/T1552.005/isovalent_cloud_metadata/isovalent_cloud_metadata.yml", "datasets/attack_techniques/T1552.007/kube_audit_get_secret/kube_audit_get_secret_old.yml", "datasets/attack_techniques/T1556.006/aws_new_mfa_method_registered_for_user/aws_new_mfa_method_registered_for_user.yml", "datasets/attack_techniques/T1556.006/azure_ad_new_mfa_method_registered_for_user/azure_ad_new_mfa_method_registered_for_user.yml", "datasets/attack_techniques/T1556/o365_disable_mfa/o365_disable_mfa.yml", "datasets/attack_techniques/T1556/o365_sso_logon_errors/o365_sso_logon_errors.yml", "datasets/attack_techniques/T1561.001/microsoft_intune_bulk_wipe/microsoft_intune_bulk_wipe.yml", "datasets/attack_techniques/T1562.001/disable_defender_operational_wineventlog/disable_defender_operational_wineventlog_old.yml", "datasets/attack_techniques/T1562.008/delete_cloudwatch_log_group/delete_cloudwatch_log_group.yml", "datasets/attack_techniques/T1562.008/put_bucketlifecycle/put_bucketlifecycle.yml", "datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/stop_delete_cloudtrail.yml", "datasets/attack_techniques/T1562.008/update_cloudtrail/update_cloudtrail.yml", "datasets/attack_techniques/T1562/azuread_disable_blockconsent_for_riskapps/azuread_disable_blockconsent_for_riskapps.yml", "datasets/attack_techniques/T1562/o365_disable_blockconsent_for_riskapps/o365_disable_blockconsent_for_riskapps.yml", "datasets/attack_techniques/T1564.008/o365/o365.yml", "datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.yml", "datasets/attack_techniques/T1567.002/snapattack/snapattack.yml", "datasets/attack_techniques/T1567/o365_sus_file_activity/o365_sus_file_activity.yml", "datasets/attack_techniques/T1580/aws_bedrock_list_foundation_model_failures/aws_bedrock_list_foundation_model_failures_old.yml", "datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/data.yml", "datasets/attack_techniques/T1580/aws_iam_old.yml", "datasets/attack_techniques/T1621/aws_mfa_disabled/aws_mfa_disabled.yml", "datasets/attack_techniques/T1621/azure_ad_multiple_denied_mfa_requests/azure_ad_multiple_denied_mfa_requests.yml", "datasets/attack_techniques/T1621/azuread/azuread.yml", "datasets/attack_techniques/T1621/multiple_failed_mfa_gws/multiple_failed_mfa_gws.yml", "datasets/attack_techniques/T1621/multiple_failed_mfa_requests/multiple_failed_mfa_requests.yml", "datasets/attack_techniques/T1621/o365_multiple_failed_mfa_requests/o365_multiple_failed_mfa_requests.yml"]

RAW_BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/master"
MEDIA_BASE_URL = f"https://media.githubusercontent.com/media/{REPO_OWNER}/{REPO_NAME}/master"

def get_raw_url(path, force_media=False):
    base = MEDIA_BASE_URL if force_media else RAW_BASE_URL
    return f"{base}/{path.lstrip('/')}"

def download_dataset_file(path):
    """Downloads a dataset file, handling GitHub LFS if needed."""
    url = get_raw_url(path)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    
    # Check for LFS pointer
    if resp.text.startswith("version https://git-lfs.github.com/spec/v1"):
        print(f"  [!] LFS detected, pulling from media for {os.path.basename(path)}...")
        url = get_raw_url(path, force_media=True)
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
    return resp

def flatten_to_ndjson(data, outfile, stats):
    """Parses data (JSON list/dict) and writes as NDJSON."""
    try:
        if isinstance(data, list):
            for item in data:
                line = json.dumps(item)
                outfile.write(line + "\n")
                stats['total_size'] += len(line) + 1
        elif isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                for item in data["Records"]:
                    line = json.dumps(item)
                    outfile.write(line + "\n")
                    stats['total_size'] += len(line) + 1
            else:
                line = json.dumps(data)
                outfile.write(line + "\n")
                stats['total_size'] += len(line) + 1
        else:
            wrap = {"raw": str(data).strip(), "source": "cloud_aggregator"}
            line = json.dumps(wrap)
            outfile.write(line + "\n")
            stats['total_size'] += len(line) + 1
    except Exception as e:
        print(f"  [!] Flattening error: {e}")

def main():
    print("--- OPERATION CLOUDBREAKER: GitHub High-Fidelity Aggregator ---")
    
    stats = {'total_size': 0, 'files_pulled': 0}
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    processed_paths = set()
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as outfile:
        for yaml_path in SEED_YAMLS:
            if stats['total_size'] >= SIZE_LIMIT:
                print("[*] Size limit reached.")
                break
                
            print(f"[*] Processing TECHNIQUE: {yaml_path}")
            try:
                y_url = get_raw_url(yaml_path)
                y_resp = requests.get(y_url, timeout=10)
                y_resp.raise_for_status()
                metadata = yaml.safe_load(y_resp.text)
                
                datasets_list = metadata.get('datasets', [])
                if not datasets_list:
                     # Some are old format or slightly different
                     print(f"  [?] No datasets found in YAML metadata.")
                     continue
                     
                for ds in datasets_list:
                    dpath = ds.get('path', '').lstrip('/')
                    if not dpath or dpath in processed_paths: continue
                    if stats['total_size'] >= SIZE_LIMIT: break
                    
                    print(f"  [>] Pulling: {dpath}")
                    try:
                        d_resp = download_dataset_file(dpath)
                        
                        # Inspect content to decide how to handle
                        content_type = d_resp.headers.get('Content-Type', '')
                        if dpath.endswith('.json') or 'json' in content_type:
                            data = d_resp.json()
                            flatten_to_ndjson(data, outfile, stats)
                        else:
                            # Likely log or txt
                            for line in d_resp.iter_lines():
                                if line:
                                    try:
                                        decoded = line.decode('utf-8', errors='ignore')
                                        # Try to see if it's already JSON per line
                                        json.loads(decoded)
                                        outfile.write(decoded + "\n")
                                        stats['total_size'] += len(decoded) + 1
                                    except:
                                        # Raw text wrap
                                        wrap = {"raw": decoded.strip(), "source": dpath}
                                        line_out = json.dumps(wrap)
                                        outfile.write(line_out + "\n")
                                        stats['total_size'] += len(line_out) + 1
                        
                        processed_paths.add(dpath)
                        stats['files_pulled'] += 1
                        print(f"  [+] Aggregated. Current volume: {stats['total_size']/1024/1024:.2f}MB")
                        
                    except Exception as e:
                        print(f"  [!] Data Error {dpath}: {e}")
                        
            except Exception as e:
                print(f"[!] YAML Metadata Error {yaml_path}: {e}")

    print("\n[!] SUCCESS: Operation Cloudbreaker Aggregation Complete.")
    print(f"[*] Final Dataset: {OUTPUT_FILE}")
    print(f"[*] Total Size: {stats['total_size']/1024/1024:.2f}MB")
    print(f"[*] Files Pulled: {stats['files_pulled']}")

if __name__ == "__main__":
    main()
