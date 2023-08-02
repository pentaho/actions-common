import os
import re
import sys
import json
import yaml
import argparse
import requests
import logging
import subprocess
from tqdm import tqdm
from boxsdk import OAuth2,Client
from artifactory import ArtifactoryPath
from requests.auth import HTTPBasicAuth
from boxsdk.exception import BoxAPIException


def get_artifact_info_json(build_name, build_number, rt_auth = (None, None), rt_base_url = None, jf_cli_rt_name = 'artifactory'):
    ''' 
    Expected Jfrog CLI is availble in the system.
    Executes these:
    1. jf config add orl-artifactory --interactive=false \
        --enc-password=false --basic-auth-only \
        --artifactory-url https://repo.orl.eng.hitachivantara.com/artifactory \
        --password --user buildguy

    2. jf rt search --server-id orl-artifactory \
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
    

    # # Define the command and arguments
    # command = [
    #     'jf', 'config', 'add', f'{jf_cli_rt_name}',
    #     '--interactive=false', '--enc-password=false', '--basic-auth-only',
    #     '--artifactory-url', f'{rt_base_url}',
    #     '--password', f'{rt_auth[0]}',
    #     '--user', f'{rt_auth[1]}'
    # ]

    # # Execute the command
    # subprocess.run(command)
    
    # Define the command and arguments
    command = ['jf', 'rt', 'search', '--server-id', f'{jf_cli_rt_name}', '--props', 
               f'build.name={build_name};build.number={build_number}',
               f'*' ]
               # f'{artifact_name}']
    
    output_file = 'artifacts.json'

    # Execute the command and capture the output
    result = subprocess.run(command, capture_output=True, text=True)

    # Parse the command output as JSON
    output_json = json.loads(result.stdout)

    # Save the JSON object to a file
    with open(output_file, 'w') as file:
        json.dump(output_json, file, indent=4)
    
    return output_json, set([artifact['path'].split('/')[-1] for artifact in output_json])


def download_artifacts_v3(artifacts_to_release, builds_output_json, auth=(None, None), rt_base_url = None):
    release_artifact_downloaded = []

    # For all the builds in artifactory that meets the build number and number name
    # we only want to download the ones that is present in the manifest file
    # Example of builds_output_json:
    # [
    # {
    #     "path": "pntpub-mvn-release-orl/pentaho/psw-ce/9.3.0.4-739/psw-ce-9.3.0.4-739.zip",
    #     "sha1": "bb1cda483ce7de00d1a59a00f7aac52b5f5206ea",
    #     "sha256": "2b197f5f40b06b10a07ec1e864abaecbced4247ddbab4f789d6492f753900201",
    #     "md5": "ca3945763c73c5b128126f2d0837d73b",
    # },
    # {
    #     "path": "pntprv-mvn-release-orl/pentaho/psw-ee/9.3.0.4-739/psw-ee-9.3.0.4-739-dist.zip",
    #     "sha1": "4d63449b3d658a1a25215fa9c8d9614f9dd0971d",
    #     "sha256": "946881250d2c073654fea5ade952cb281222809164cc7805cbaaa7c3ecd5a37f",
    #     "md5": "e4df9f24a93cface78bdeada19ae4bf2",
    # ...

    # Example of artifacts_to_release:
    # {'pad-ee-9.3.0.4-739-dist.zip': 'ee/client-tools',
    #  'pdi-ee-client-9.3.0.4-739-dist.zip': 'ee/client-tools',
    #  'pentaho-analysis-ee-9.3.0.4-739-dist.zip': 'ee/client-tools',
    # ...
            
    for build_artifact in tqdm(builds_output_json):
        file_name = build_artifact['path']
        if build_artifact['path'].split('/')[-1] in artifacts_to_release.keys():

            logging.info(f"Downloading {file_name}")

            path = build_artifact['path']
            sha1 = build_artifact['sha1']
            sha256 = build_artifact['sha256']
            md5 = build_artifact['md5']

            file_name = build_artifact['path'].split('/')[-1]
            check_sum_file_name = path.split('/')[-1]+'.sum'

            # download artifact
            rt_path = ArtifactoryPath(
                f"{rt_base_url}/"+path, auth=auth, auth_type=HTTPBasicAuth
            )
            
            # Only download artifact if it doesn't exists
            if not os.path.exists(file_name):
                logging.info(f'Downloading {file_name} from {rt_path}.')
                rt_path.writeto(out=file_name, progress_func=None)
                logging.info(f'Download complete.')
            
            # Only download artifact if it doesn't exists
            if not os.path.exists(check_sum_file_name):
                logging.info(f'Saving check sum file {check_sum_file_name}')
                with open(check_sum_file_name, 'w') as f:
                    f.write('sha1='+ sha1 +'\n')
                    f.write('sha256='+ sha256 +'\n')
                    f.write('md5='+ md5+'\n')
                
        release_artifact_downloaded.append(file_name)
                
    logging.info(f'Release artifacts {release_artifact_downloaded}')
    return release_artifact_downloaded


def replace_versions(text, replacement_word):
    pattern = r'\${.*?}'
    return re.sub(pattern, replacement_word, text)


def get_manifest_yaml(version, manifest_file = None):
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
    logging.info(f'Read manifest {result}')
    return result


def get_manifest_buildinfo_intersect(file_folder_dict, builds_output_json):
    # This function picks the artifacts that's only both in builds_output_json and file_folder_dict
    # returns a dictionary of files to release as key, and the path correspond to box as value
    d = {}
    manifest_files = set(file_folder_dict.keys()).intersection(set([artifact['path'].split('/')[-1] for artifact in builds_output_json]))
    manifest_files
    for file_to_release in manifest_files:
        d[file_to_release] = file_folder_dict[file_to_release]
        d[file_to_release + '.sum'] =  file_folder_dict[file_to_release]
    return d


def set_box_client(client_id, client_secret, box_subject_id):
    token=generate_access_token(client_id,client_secret,box_subject_id)
    oauth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        access_token=token,  
    )
    return Client(oauth)


def upload_one_artifact_to_box(folder_id, file_name, client):
    try:
        with open(file_name, 'rb') as file:
            box_file = client.folder(folder_id).upload_stream(file, file_name)
            logging.info(f'Uploaded file: {file_name} into folder id: {folder_id}')

    except BoxAPIException as e:
        # if the file already exists, update the contents of it
        if e.status == 409:
            logging.WARNING(f'File exist name {file_name} already exist.')
            file_id = e.context_info['conflicts']['id']
            updated_file = client.file(file_id).update_contents(file_name)
        return updated_file



def generate_access_token(client_id, client_secret, box_subject_id):
    url = "https://api.box.com/oauth2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "client_id": client_id,
        "client_secret":client_secret,
        "grant_type": "client_credentials",
        "box_subject_type": "enterprise",
        "box_subject_id": box_subject_id,
    }

    response = requests.post(url, headers=headers, data=data)
    response_data = response.json()
    return response_data['access_token']

def box_create_one_folder(parent_folder_id, folder_name_to_create, client):
    
    try:
        folder = client.folder(parent_folder_id).create_subfolder(folder_name_to_create)
        return folder
    except BoxAPIException as e:
        # if the folder already exists, return the Folder object
        if e.code == 'item_name_in_use': 
            logging.info(f'Folder name {folder_name_to_create} already exist.')
            folder = client.folder(folder_id=e.context_info['conflicts'][0]['id']).get()
            return folder
        return None

def box_create_folder(client, yaml_data, box_folder_parent_id=None, path='', result={}):

    for key, value in yaml_data.items():
        if isinstance(value, dict):
            folder_obj = box_create_one_folder(box_folder_parent_id, key, client)
            print(f'Created folder with parent id as {box_folder_parent_id} with name {key}')
            result[os.path.join(path, key)] = folder_obj
            box_create_folder(client, yaml_data[key], box_folder_parent_id=folder_obj.id, path=os.path.join(path, key), result=result)
            
        elif isinstance(value, list):
            folder_obj = box_create_one_folder(box_folder_parent_id, key, client)
            print(f'Create folder with parent id as {box_folder_parent_id} with name {key}')
            current_path = os.path.join(path, key)
            result[os.path.join(path, key)] = folder_obj
        
    return result

def upload_to_box(client, artifacts_to_release, artifact_to_box_path):
    for artifact, target_box_path in tqdm(artifacts_to_release.items()):
        print(f'Uploading {artifact} up to {artifact_to_box_path[target_box_path]}')
        upload_one_artifact_to_box(artifact_to_box_path[target_box_path].id, artifact, client)
        

if __name__ == '__main__':

    ########### Parse args #################
    parser = argparse.ArgumentParser()

    parser.add_argument("--client_id", action="store")
    parser.add_argument("--client_secret", action="store", help="box client secret")
    parser.add_argument("--box_subject_id", action="store", help="box box subject id")
    parser.add_argument("--build_name", action="store", help="build name")
    parser.add_argument("--build_number", action="store", help="artifactory build_number")
    parser.add_argument("--rt_auth_username", action="store", help="box client secret")
    parser.add_argument("--rt_auth_password", action="store", help="box client secret")
    parser.add_argument("--box_parent_folder_name", action="store", help="Parent folder to the artifacts on box, example: 9.5.0.0")
    parser.add_argument("--manifest_file_path", action="store", help="pass in a manifest file path relative to current workingdir")
    parser.add_argument("--rt_base_url", action="store", help="artifactory base url, ending with /artifactory ")
    parser.add_argument("--jf_cli_rt_name", action="store", help="From the jf CLI config, the alias of the artifactory build info resides")
    parser.add_argument("--logging_level", action="store", default="INFO", help="Set logging level")
    parser.add_argument("--box_root_folder_name", action="store", default="CI", help="This is default to CI folder")

    args = parser.parse_args()

    client_id = args.client_id
    client_secret = args.client_secret
    box_subject_id = args.box_subject_id
    build_name = args.build_name  # for rt buildinfo query
    build_number = args.build_number  # for rt buildinfo query
    rt_auth = (args.rt_auth_username, args.rt_auth_password)
    box_parent_folder_name = args.box_parent_folder_name
    manifest_file_path = args.manifest_file_path
    rt_base_url = args.rt_base_url
    logging_level = args.logging_level
    box_root_folder_name = args.box_root_folder_name
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
        format= '[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    ####### End of logging #######


    ###### Upload to box ##########
    # downloads artifacts
    builds_output_json, artifacts_in_build_info = get_artifact_info_json(build_name, build_number, rt_auth=rt_auth)
    file_folder_dict = process_manifest_yaml(get_manifest_yaml(build_number, manifest_file = manifest_file_path))
    artifacts_to_release = get_manifest_buildinfo_intersect(file_folder_dict, builds_output_json)
    downloaded_artifacts = download_artifacts_v3(artifacts_to_release, builds_output_json, auth=rt_auth, rt_base_url = rt_base_url)

    # set up box client
    box_client = set_box_client(client_id, client_secret, box_subject_id)

    # create root folder, defaults to CI
    root_folder = box_create_one_folder('0', box_root_folder_name, box_client)
    parent_folder = box_create_one_folder(root_folder.id, box_parent_folder_name, box_client)

    # uploading to box
    yaml_data = get_manifest_yaml(build_number, manifest_file = manifest_file_path)
    artifact_to_box_path = box_create_folder(box_client, yaml_data, box_folder_parent_id=parent_folder.id)
    upload_to_box(box_client, artifacts_to_release, artifact_to_box_path)
    ######## End upload to box #########



