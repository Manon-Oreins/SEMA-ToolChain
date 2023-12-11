# TODO manon run setup.py to update package etc ?
echo "Moving to tests directory:"
echo "Compiling C code:"
cd tests; make all; cd ..;

echo "Running Linux tests:"
python3 tests/tests/linux/linux_test.py > "/sema-scdg/application/tests/reports/memory_reports/$(date +"%Y%m%d_%H%M%S")_test.log" 2> "/sema-scdg/application/tests/reports/memory_reports/$(date +"%Y%m%d_%H%M%S")_test.err"

# echo "Cleaning up:"
# cd tests; make clean; cd ..;