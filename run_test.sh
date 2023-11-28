# TODO manon run setup.py to update package etc ?

cd src/SemaSCDG/
echo "Compiling C code:"
cd tests; make all; cd ..;
echo "Running Linux tests:"
python3 tests/tests/linux/linux_test.py

# echo "Cleaning up:"
# cd tests; make clean; cd ..;