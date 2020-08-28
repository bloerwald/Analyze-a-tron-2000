```bash
mkdir deps && curl --location https://github.com/avast/retdec/releases/download/v4.0/retdec-v4.0-ubuntu-64b.tar.xz | tar xJC deps
mkdir build && cmake -S . -B build -DCMAKE_PREFIX_PATH=$PWD/deps/retdec
cmake --build build
./build/post_process_dumped_exe ~/WowB35360.exe ~/WowB35360_dump_SCY.exe ~/WowB35360_pp.exe
```
