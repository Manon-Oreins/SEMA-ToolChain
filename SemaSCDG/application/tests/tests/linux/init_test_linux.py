# TODO manon: faire une mini method avec les techniques d'explo de base pour genere des outputs vers expected_output (permet d'eviter les pbs lier au differente machine)

# Create the destination folder if it doesn't exist
if not os.path.exists(expected_linux_folder):
    os.makedirs(expected_linux_folder)

# Walk through the source folder recursively
for foldername, subfolders, filenames in os.walk(args.exp_dir + "/to_test/"):
    for filename in filenames:
        # Create the full path for the source and destination files
        src_file  = os.path.join(foldername, filename)
        dest_file = os.path.join(expected_linux_folder, os.path.relpath(src_file, args.exp_dir + "/to_test/"))

        # Copy the file
        shutil.copy2(src_file, dest_file)
        LOGGER.info(f"Copied: {src_file} to {dest_file}")