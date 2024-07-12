import requests
import hashlib
import re
import os
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    try:
        # Get the expected SHA-256 hash value of the VLC installer
        expected_sha256 = get_expected_sha256()
        logging.info(f"Expected SHA-256: {expected_sha256}")

        # Download (but don't save) the VLC installer from the VLC website
        installer_data = download_installer()
        logging.info("Installer downloaded successfully.")

        # Verify the integrity of the downloaded VLC installer by comparing the
        # expected and computed SHA-256 hash values
        if installer_ok(installer_data, expected_sha256):
            logging.info("Installer integrity verified.")

            # Save the downloaded VLC installer to disk
            installer_path = save_installer(installer_data)
            logging.info(f"Installer saved to {installer_path}.")

            # Silently run the VLC installer
            run_installer(installer_path)
            logging.info("Installer is running.")

            # Delete the VLC installer from disk
            delete_installer(installer_path)
            logging.info("Installer deleted.")

        else:
            logging.error("Installer integrity verification failed.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    furl = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe.sha256'
    try:
        response = requests.get(furl)
        response.raise_for_status()
        file_content = response.text
        match = re.search(r"([a-fA-F0-9]{64})\s", file_content)
        if match:
            return match.group(1)
        else:
            raise ValueError("SHA-256 hash not found in the file.")
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to retrieve the expected SHA-256 hash: {e}")

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    furl = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'
    try:
        response = requests.get(furl)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to download the VLC installer: {e}")

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expected SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    computed_sha256 = hashlib.sha256(installer_data).hexdigest()
    return computed_sha256 == expected_sha256

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_name = "vlc-3.0.17.4-win64.exe"
    file_path = os.path.join(script_dir, file_name)
    try:
        with open(file_path, 'wb') as file: 
            file.write(installer_data)
        return file_path
    except IOError as e:
        raise RuntimeError(f"Failed to save the installer: {e}")

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    try:
        subprocess.run([installer_path, '/L=1033', '/S'], check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to run the installer: {e}")

def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    try:
        os.remove(installer_path)
    except OSError as e:
        raise RuntimeError(f"Failed to delete the installer: {e}")

if __name__ == '__main__':
    main()
