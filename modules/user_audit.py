#!/usr/bin/python

__version__ = "1.0"

import datetime
import pprint

from shared.api_utils import rate_limit_get
from shared.csv_utils import build_csv, cq_build_csv
from shared.menu_utils import audit_checker, prep_user_csv


def run(client):
    """
    Perform a comprehensive user extension audit of the RingCentral account.
    Exports results to CSV files in the AuditResults/ directory.
    """
    try:
        client.authenticate()
    except Exception as e:
        print(f"Token refresh failed: {e}. Proceeding with existing token.")

    start_time = datetime.datetime.now()
    date_stamp = start_time.strftime("%Y-%m-%d_%H-%M")

    print(f'\nUser Extension Audit')
    print(f'Start Time: {start_time}\n')

    while True:
        audit_name = input("Enter a name for this audit (files will be auto-datestamped): ").strip()
        if audit_name:
            audit_file_name = audit_name.replace(" ", "_").replace("/", "-")
            break
        print("Audit name cannot be empty.")

    # Fetch account-level company name as fallback for per-user contact.company
    account_resp = rate_limit_get(client, '/restapi/v2/account/~')
    account_company = account_resp.get('companyName') if account_resp else None

    # Filter and field selection
    filter_user_count, user_count, built_url = audit_checker(client, '/restapi/v1.0/account/~/extension')
    fields = prep_user_csv()

    datalist = []
    cq_datalist = []
    audited = 0

    # Fetch the (filtered) extension list
    ext_resp = rate_limit_get(client, built_url)
    records = ext_resp.get('records', [])

    for record in records:
        ext_id = record['id']

        # Core user data
        user_data = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}')
        if user_data is None:
            continue

        ext_name = user_data.get('name')
        ext_type = user_data.get('type')

        # Initialise optional field variables
        ext_did = None
        ext_assigned_role = None
        ext_dnd_status = None
        ext_bhr_fw_dest = None
        ext_ahr_fw_dest = None
        ext_device_name = ext_device_model = ext_device_serial = ext_device_status = None
        cq_bhr_fw_dest = None
        cq_bhr_fw_type = None

        # Direct Number
        if fields['did']:
            did_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/phone-number?usageType=DirectNumber')
            if did_resp:
                for phone in did_resp.get('records', []):
                    if phone.get('primary'):
                        ext_did = phone.get('phoneNumber')
                        break
                if ext_did is None and did_resp.get('records'):
                    ext_did = did_resp['records'][0].get('phoneNumber')

        # Assigned Role
        if fields['user_assigned_role']:
            role_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/assigned-role')
            if role_resp:
                roles = role_resp.get('records', [])
                if roles:
                    ext_assigned_role = roles[0].get('displayName')

        # DND / Presence
        if fields['dnd_state']:
            presence_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/presence')
            if presence_resp:
                ext_dnd_status = presence_resp.get('dndStatus')

        # Business Hours Forwarding
        if fields['bhr_fw']:
            bhr_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/answering-rule/business-hours-rule')
            if bhr_resp is not None:
                bhr_missed = bhr_resp.get('missedCall')
                bhr_voicemail = bhr_resp.get('voicemail', {}).get('enabled')

                if ext_type == 'Department':
                    # Call Queue forwarding
                    hold_action = bhr_resp.get('queue', {}).get('holdTimeExpirationAction')
                    if hold_action == 'TransferToExtension':
                        for transfer in bhr_resp.get('queue', {}).get('transfer', []):
                            if transfer.get('action') == 'HoldTimeExpiration':
                                dest_name = transfer.get('extension', {}).get('name')
                                ext_bhr_fw_dest = dest_name
                                cq_bhr_fw_dest = dest_name
                                cq_bhr_fw_type = 'Transfer to Extension'
                    elif hold_action == 'Voicemail':
                        ext_bhr_fw_dest = 'Call Queue Voicemail'
                        cq_bhr_fw_dest = 'Call Queue Voicemail'
                        cq_bhr_fw_type = 'Call Queue Voicemail'
                    elif hold_action == 'UnconditionalForwarding':
                        for fwd in bhr_resp.get('queue', {}).get('unconditionalForwarding', []):
                            ext_bhr_fw_dest = fwd.get('phoneNumber')
                            cq_bhr_fw_dest = ext_bhr_fw_dest
                            cq_bhr_fw_type = 'External Number'
                    else:
                        ext_bhr_fw_dest = 'Unknown'

                elif ext_type == 'User':
                    if bhr_voicemail:
                        ext_bhr_fw_dest = 'User Voicemail'
                    elif bhr_missed:
                        dest_type = bhr_resp.get('missedCall', {}).get('actionType')
                        if dest_type == 'ConnectToExtension':
                            fw_id = bhr_resp.get('missedCall', {}).get('extension', {}).get('id')
                            fw_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{fw_id}')
                            ext_bhr_fw_dest = fw_resp.get('name') if fw_resp else None
                        elif dest_type == 'ConnectToExternalNumber':
                            ext_bhr_fw_dest = bhr_resp.get('missedCall', {}).get('externalNumber', {}).get('phoneNumber')
                    else:
                        ext_bhr_fw_dest = 'No Business Hours Rule Exists'
                else:
                    ext_bhr_fw_dest = 'No Business Hours Rule Exists'
            else:
                ext_bhr_fw_dest = 'No Business Hours Rule'

        # After Hours Forwarding
        if fields['ahr_fw']:
            ahr_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/answering-rule/after-hours-rule')
            if ahr_resp is not None:
                ahr_mode = ahr_resp.get('callHandlingAction')
                if ahr_mode == 'TakeMessagesOnly':
                    ext_ahr_fw_dest = 'User Voicemail'
                elif ahr_mode == 'TransferToExtension':
                    ahr_fw_id = ahr_resp.get('transfer', {}).get('extension', {}).get('id')
                    ahr_fw_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ahr_fw_id}')
                    ext_ahr_fw_dest = ahr_fw_resp.get('name') if ahr_fw_resp else None
                elif ahr_mode == 'UnconditionalForwarding':
                    ext_ahr_fw_dest = ahr_resp.get('unconditionalForwarding', {}).get('phoneNumber')
                elif ahr_mode == 'PlayAnnouncementOnly':
                    ext_ahr_fw_dest = 'Play Announcement Message'
                elif ahr_mode == 'ForwardCalls':
                    ext_ahr_fw_dest = 'Ring Devices'
                else:
                    ext_ahr_fw_dest = ahr_mode
            else:
                ext_ahr_fw_dest = 'No After Hours Rule Exists'

        # Device Info
        if fields['device_info']:
            device_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/extension/{ext_id}/device?type=HardPhone')
            if device_resp:
                devices = device_resp.get('records', [])
                if devices:
                    d = devices[0]
                    ext_device_name = d.get('name')
                    ext_device_model = d.get('model', {}).get('name')
                    ext_device_serial = d.get('serial')
                    ext_device_status = d.get('status')
                else:
                    ext_device_name = ext_device_model = ext_device_serial = ext_device_status = 'No Device'

        # Call Queue member details
        if ext_type == 'Department':
            cq_resp = rate_limit_get(client, f'/restapi/v1.0/account/~/call-queues/{ext_id}/presence')
            if cq_resp:
                members = cq_resp.get('records', [])
                if members:
                    for member in members:
                        cq_member_name = member.get('member', {}).get('name', 'No member')
                        cq_row = {
                            'Call Queue Name':              user_data.get('name'),
                            'Call Queue Extension':         user_data.get('extensionNumber'),
                            'Call Queue Member':            cq_member_name,
                            'Member Extension':             member.get('member', {}).get('extensionNumber', ''),
                            'Accept Queue Calls?':          member.get('acceptQueueCalls', ''),
                            'Accept Current Queue Calls?':  member.get('acceptCurrentQueueCalls', ''),
                            'Forward Destination Type':     cq_bhr_fw_type,
                            'Forward Destination':          cq_bhr_fw_dest,
                        }
                        cq_datalist.append(cq_row)
                else:
                    cq_row = {
                        'Call Queue Name':              user_data.get('name'),
                        'Call Queue Extension':         user_data.get('extensionNumber'),
                        'Call Queue Member':            'No members',
                        'Member Extension':             '',
                        'Accept Queue Calls?':          '',
                        'Accept Current Queue Calls?':  '',
                        'Forward Destination Type':     cq_bhr_fw_type,
                        'Forward Destination':          cq_bhr_fw_dest,
                    }
                    cq_datalist.append(cq_row)

        # Build row for this extension
        row = {
            **({'User ID': ext_id} if fields['id'] else {}),
            **({'Extension Name': ext_name} if fields['name'] else {}),
            **({'Extension Number': user_data.get('extensionNumber')} if fields['number'] else {}),
            **({'Extension Direct Number': ext_did} if fields['did'] else {}),
            **({'Extension Status': user_data.get('status')} if fields['status'] else {}),
            **({'Extension Type': ext_type} if fields['type'] else {}),
            **({'Site': user_data.get('site', {}).get('name')} if fields['site'] else {}),
            **({'Company': user_data.get('contact', {}).get('company') or account_company} if fields['company'] else {}),
            **({'Department': user_data.get('contact', {}).get('department')} if fields['department'] else {}),
            **({'Job Title': user_data.get('contact', {}).get('jobTitle')} if fields['job_title'] else {}),
            **({'Email': user_data.get('contact', {}).get('email')} if fields['email'] else {}),
            **({'DND Status': ext_dnd_status} if fields['dnd_state'] else {}),
            **({'Business Hours Forward Destination': ext_bhr_fw_dest} if fields['bhr_fw'] else {}),
            **({'After Hours Forward Destination': ext_ahr_fw_dest} if fields['ahr_fw'] else {}),
            **({'User Assigned Role': ext_assigned_role} if fields['user_assigned_role'] else {}),
            **({'Is Administrator?': user_data.get('permissions', {}).get('admin', {}).get('enabled')} if fields['admin_check'] else {}),
            **({'Setup Wizard State': user_data.get('setupWizardState')} if fields['setup_wizard_status'] else {}),
            **({'Device Name': ext_device_name} if fields['device_info'] else {}),
            **({'Device Model': ext_device_model} if fields['device_info'] else {}),
            **({'Device Serial': ext_device_serial} if fields['device_info'] else {}),
            **({'Device Status': ext_device_status} if fields['device_info'] else {}),
        }
        datalist.append(row)
        audited += 1

        target = filter_user_count if filter_user_count else user_count
        print(f'\nAudited {audited} of {target}')
        print(f'### {ext_name} ###')
        pprint.pprint(row, indent=2, sort_dicts=False)

        # Write incrementally so progress is not lost on interrupt
        build_csv(datalist, audit_file_name, date_stamp)
        if cq_datalist:
            cq_build_csv(cq_datalist, audit_file_name, date_stamp)

    end_time = datetime.datetime.now()
    runtime = (end_time - start_time).total_seconds()
    m, s = divmod(runtime, 60)

    print(f'\n{"=" * 80}')
    print("User Extension Audit complete.")
    if filter_user_count:
        print(f'Audited {audited} of {filter_user_count} filtered extensions.')
    else:
        print(f'Audited {audited} of {user_count} extensions.')
    print(f'End Time: {end_time}')
    print(f'Runtime:  {int(m)}m {int(s)}s')
    print(f'{"=" * 80}\n')
