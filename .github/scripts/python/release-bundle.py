import os
import re
import sys
import json
import yaml
import argparse
import requests
import logging
import subprocess
from artifactory import ArtifactoryPath
from requests.auth import HTTPBasicAuth

def get_artifact_info_json(build_name, build_number, rt_auth=(None, None), rt_base_url=None, jf_cli_rt_name=None):
    ''' 
    Expected Jfrog CLI is availble in the system.
    Executes these:
    1. jf config add one-artifactory --interactive=false \
        --enc-password=false --basic-auth-only \
        --artifactory-url https://one.hitachivantara.com/artifactory \
        --password --user buildguy

    2. jf rt search --server-id one-artifactory \
        --props "build.name=pdi-xxx-9.5.1.0;build.number=86" "*-9.5.1.0-86.zip" \
        > builds.json

    Alternative way: Use ArtifactoryBuildManager https://github.com/devopshq/artifactory#builds
    
    ^^^^^^^^^^^^^
    from artifactory import ArtifactoryBuildManager

    arti_build = ArtifactoryBuildManager(
        orl_url, auth=auth_orl)

    # Get all builds,space turns into %
    all_builds = arti_build.builds
    print(all_builds)
    ^^^^^^^^^^^^^
    '''

    if jf_cli_rt_name is None:
        jf_cli_rt_name = 'artifactory'

        # adding artifactory cli config
        logging.info(f'Adding artifactory CLI name {jf_cli_rt_name}')

        # Define the command and arguments
        command = [
            'jf', 'config', 'add', f'{jf_cli_rt_name}',
            '--interactive=false', '--enc-password=false', '--basic-auth-only',
            '--artifactory-url', f'{rt_base_url}/',
            '--user', f'{rt_auth[0]}',
            '--password', f'{rt_auth[1]}'
        ]
        # Execute the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True)

        logging.debug(result)

    # Define jf command and arguments
    command = ['jf', 'rt', 'search', '--server-id', f'{jf_cli_rt_name}', '--props',
               f'build.name={build_name};build.number={build_number}',
               f'*']

    output_file = 'artifacts.json'

    # Execute the command and capture the output
    result = subprocess.run(command, capture_output=True, text=True)

    # log result
    logging.debug(f'jf execution result {result}')

    # Parse the command output as JSON
    output_json = json.loads(result.stdout)

    # Save the JSON object to a file
    with open(output_file, 'w') as file:
        json.dump(output_json, file, indent=4)

    logging.debug(f'Artifacts in artifactory with build.name={build_name};build.number={build_number}: {output_json}')

    return output_json, set([artifact['path'].split('/')[-1] for artifact in output_json])

def replace_versions(text, replacement_word):
    pattern = r'\${.*?}'
    return re.sub(pattern, replacement_word, text)

def get_manifest_yaml(version, manifest_file=None):
    with open(manifest_file, 'r') as f:
        file_content = f.read()

    new_file_content = replace_versions(file_content, version)
    yaml_obj = yaml.safe_load(new_file_content)
    return yaml_obj

def process_manifest_yaml(yaml_data, parent=None):
    '''
    Returns a dict with parent as value, child as key.
    {'pad-ee-9.5.1.0-dist.zip': 'ee/client-tools',
     'pdi-ee-client-9.5.1.0-dist.zip': 'ee/client-tools',
     'pentaho-analysis-ee-9.5.1.0-dist.zip': 'ee/client-tools',
     'pentaho-big-data-ee-package-9.5.1.0-dist.zip': 'ee/client-tools',
     'pme-ee-9.5.1.0-dist.zip': 'ee/client-tools',
     'prd-ee-9.5.1.0-dist.zip': 'ee/client-tools',
     ...}
    '''
    result = {}
    for key, value in yaml_data.items():
        current_key = key if parent is None else f"{parent}/{key}"
        if isinstance(value, dict):
            result.update(process_manifest_yaml(value, parent=current_key))
        elif isinstance(value, list):
            for item in value:
                if '$' not in item or '{' not in item:
                    result[item] = current_key
    return result

def get_manifest_buildinfo_intersect(file_folder_dict, builds_output_json):
    # This function picks the artifacts that's only both in builds_output_json and file_folder_dict
    # returns a dictionary of files to release as key, and the path correspond to box as value
    d = {}
    files_to_be_promoted = set(file_folder_dict.keys()).intersection(
        set([artifact['path'].split('/')[-1] for artifact in builds_output_json]))
    # Extracting other values for the files to be promoted

    files_to_be_promoted_details = []
    for artifact in builds_output_json:
        file_name = artifact['path'].split('/')[-1]
        if file_name in files_to_be_promoted:
            # Extract other values you're interested in
            details = {
            "path": artifact['path'],
            "sha256": artifact['sha256']
            }
            files_to_be_promoted_details.append(details)
    
    # Sanity check
    files_only_in_manifest = set(file_folder_dict.keys()) - set(
        [artifact['path'].split('/')[-1] for artifact in builds_output_json])

    if files_only_in_manifest:
        logging.warning(f'Found some artifacts only present in manifest file {files_only_in_manifest}')

    logging.info(f'Files to be added in release bundle {files_to_be_promoted}')

    for file_to_release in files_to_be_promoted:
        d[file_to_release] = file_folder_dict[file_to_release]
        d[file_to_release + '.sum'] = file_folder_dict[file_to_release]

    return files_to_be_promoted_details

def create_release_bundle_from_artifacts( artifacts_to_release ,release_bundle_name ,release_bundle_version ,signing_key_name, rt_auth=(None, None), arti_host=None):
    
    if dry_run is True:
        logging.info(f'[Dry run] : Creating release bundle "{relese_bundle_name}" with {release_bundle_version} version...with Source Type artifacts')
    else:
        artifacts_file = json.dumps({
        "release_bundle_name": release_bundle_name,
        "release_bundle_version": release_bundle_version,
        "skip_docker_manifest_resolution": False,
        "source_type": "artifacts",
        "source": {
            "artifacts": artifacts_to_release
            }
        },indent=2)

        logging.info(f"artifact json file {artifacts_file}")
        
        # Define the URL
        url = f'{arti_host}/lifecycle/api/v2/release_bundle'

        # Define headers
        headers = {
            'X-JFrog-Signing-Key-Name': signing_key_name,
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {rt_auth[1]}'
        }

        # Make the request
        response = requests.post(url, headers=headers, data=artifacts_file)

        # Check the response
        if response.status_code == 200:
            logging.info(f'Created release bundle "{relese_bundle_name}" with {release_bundle_version} version')
            logging.debug(f"Request successful and message: {response.text}")
        else:
            logging.info(f"Request failed with status code {response.status_code} and message: {response.text}")

def create_release_bundle_from_builds( build_name ,build_number,release_bundle_name ,release_bundle_version ,signing_key_name, rt_auth=(None, None), arti_host=None):
    
    if dry_run is True:
        logging.info(f'[Dry run] : Creating release bundle "{relese_bundle_name}" with {release_bundle_version} version... with Source Type Builds')
    else:
        builds_file=json.dumps({
        "release_bundle_name": release_bundle_name,
        "release_bundle_version": release_bundle_version,
        "skip_docker_manifest_resolution": False,
        "source_type": "builds",
        "source": {
            "builds": [
                {
                    "build_name": build_name,
                    "build_number": build_number,
                    "include_dependencies": False
                }
            ]
            }
        },indent=2)

        logging.info(f"builds json file {builds_file}")
        
        # Define the URL
        url = f'{arti_host}/lifecycle/api/v2/release_bundle'

        # Define headers
        headers = {
            'X-JFrog-Signing-Key-Name': signing_key_name,
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {rt_auth[1]}'
        }

        # Make the request
        response = requests.post(url, headers=headers, data=builds_file)

        # Check the response
        if response.status_code == 200:
            logging.info(f'Created release bundle "{relese_bundle_name}" with {release_bundle_version} version')
            logging.debug(f"Request successful and message: {response.text}")
        else:
            logging.info(f"Request failed with status code {response.status_code} and message: {response.text}")

if __name__ == '__main__':

    ########### Parse args #################
    parser = argparse.ArgumentParser()

    parser.add_argument("--build_name", action="store", help="build name")
    parser.add_argument("--build_version", action="store", help="build version such as: 9.5.1.0")
    parser.add_argument("--build_number", action="store", help="artifactory build_number")
    parser.add_argument("--rt_auth_username", action="store", default="buildguy", help="box client secret")
    parser.add_argument("--rt_auth_password", action="store", help="artifactory password")
    parser.add_argument("--manifest_file_path", action="store",help="pass in a manifest file path relative to current workingdir")
    parser.add_argument("--rt_base_url", action="store", help="artifactory base url, ending with /artifactory ")
    parser.add_argument("--jf_cli_rt_name", action="store",help="From the jf CLI config, the alias of the artifactory build info resides")
    parser.add_argument("--logging_level", action="store", default="INFO", help="Set logging level")
    parser.add_argument("--dry_run", default=True, type=lambda x: (str(x).lower() == 'true'),help="Executes the workflow as a dry run in the release. No real changes should occur.")
    parser.add_argument("--release_bundle_name", action="store",help="release bundle name")
    parser.add_argument("--release_bundle_version", action="store",help="release bundle version")
    parser.add_argument("--signing_key_name",action="store",help="release bundle signing key name")
    parser.add_argument("--arti_host", action="store", help="artifactory base url")
    parser.add_argument("--release_method", action="store", help="source type to create release bundle")

    args = parser.parse_args()

    build_name = args.build_name  # for rt buildinfo query
    build_number = args.build_number  # for rt buildinfo query
    build_version = args.build_version
    rt_auth = (args.rt_auth_username, args.rt_auth_password)
    manifest_file_path = args.manifest_file_path
    rt_base_url = args.rt_base_url
    jf_cli_rt_name = args.jf_cli_rt_name
    logging_level = args.logging_level
    dry_run = args.dry_run
    relese_bundle_name=args.release_bundle_name
    release_bundle_version=args.release_bundle_version
    signing_key_name=args.signing_key_name
    arti_host=args.arti_host
    release_method=args.release_method

    ############ End parsing args #############

    ######### logging ############
    string_to_level = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    logging.basicConfig(
        level=string_to_level[logging_level],
        format='[%(asctime)s] [%(filename)s:%(lineno)d] %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    ####### End of logging #######

    # determine the build suffix 9.5.1.0-124

    build_suffix = build_version + '-' + build_number
    
    if release_method == "artifacts":

        builds_output_json, artifacts_in_build_info = get_artifact_info_json(build_name, build_number, rt_auth=rt_auth,
                                                                            rt_base_url=rt_base_url,
                                                                            jf_cli_rt_name=jf_cli_rt_name)
        file_folder_dict = process_manifest_yaml(get_manifest_yaml(build_suffix, manifest_file=manifest_file_path))
        artifacts_to_release_details = get_manifest_buildinfo_intersect(file_folder_dict, builds_output_json)
        
        # if there are no files to deploy, exit process
        if not artifacts_to_release_details:
            logging.warning(
                f'There are no artifacts to be promoted with build name:{build_name}, build number: {build_number}, build '
                f'version {build_version}')
            sys.exit(1)
            
        create_release_bundle_from_artifacts( artifacts_to_release_details, relese_bundle_name, release_bundle_version, signing_key_name, rt_auth=rt_auth, arti_host=arti_host )
   
    elif release_method == "builds":
       
        create_release_bundle_from_builds( build_name, build_number, relese_bundle_name, release_bundle_version, signing_key_name, rt_auth=rt_auth,arti_host=arti_host )
