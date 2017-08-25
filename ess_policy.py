#!/usr/bin/python
# coding: utf-8

DOCUMENTATION = '''
---
module: ess_policy
short_description: Set policy to Elasticsearch Service
description:
    - Set policy to Elasticsearch Service
options:
  domain:
    description:
      - Domain name
    required: false
  policy_json:
    description:
      - A properly json formatted policy as string (mutually exclusive with C(policy_document),
        see https://github.com/ansible/ansible/issues/7005#issuecomment-42894813 on how to use it properly)
    required: true
  state:
    description:
      - Whether to create or delete the IAM policy.
    required: false
    default: present
    choices: [ "present", "absent" ]
author:
    - "Ryo Manzoku (@rmanzoku)"
extends_documentation_fragment: aws
'''

EXAMPLES = '''
# Update a policy to the domain from json file
tasks:
- name: Update a policy to the domain
  ess_policy:
    domain: example
    state: present
    policy_json: "{{ lookup('file', 'policy.json') }}"
'''

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False

import json
import ast
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import ec2_argument_spec, boto3_conn, get_aws_connection_info


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            domain=dict(type='str', required=True),
            policy_json=dict(type='str', required=True),
            state=dict(default='present', type='str', choices=['present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)
    changed = False

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTOCORE:
        module.fail_json(msg='botocore required for this module')

    # Connect to AWS
    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        conn = boto3_conn(module, conn_type="client", resource="es", region=region,
                          **aws_connect_kwargs)
    except NoCredentialsError as ex:
        module.fail_json(msg=ex.message)

    # Absent
    if module.params['state'] == "absent":
        policy = "{}"
        res = conn.update_elasticsearch_domain_config(
            DomainName=module.params['domain'],
            AccessPolicies=policy
        )
        changed = True
        module.exit_json(changed=changed)

    # Present
    else:
        # Check current policy
        try:
            res = conn.describe_elasticsearch_domain_config(DomainName=module.params['domain'])
        except ClientError as ex:
            module.fail_json(msg=ex.response['Error']['Message'])

        current_policy_dict = json.loads(res['DomainConfig']['AccessPolicies']['Options'])
        desired_policy_dict = ast.literal_eval(module.params['policy_json'])

        # The desired policy is same as current policy
        if current_policy_dict == desired_policy_dict:
            changed = False

        else:
            # Update policy
            try:
                res = conn.update_elasticsearch_domain_config(
                    DomainName=module.params['domain'],
                    AccessPolicies=json.dumps(obj=desired_policy_dict)
                )
                changed = True

            except ClientError as ex:
                module.fail_json(msg=ex.response['Error']['Message'])

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
