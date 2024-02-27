clear

mkdir -p build

cd build
cmake ..
cmake --build .

if [ $? -eq 0 ]; then
    # clear
    ./rsa_test
fi