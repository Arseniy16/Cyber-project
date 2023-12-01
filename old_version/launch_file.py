import subprocess

def launch_exe(exe_path, args):
    command = [exe_path] + args

    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to launch {exe_path}")
        print(e)

# Example usage
exe_path = "/home/arseniy/Crypto-prj/Blowfish/blowfish_modes.exe"
arguments = ["100", "8", "3"]

launch_exe(exe_path, arguments)
