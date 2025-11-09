perf record -F 99 -g -- ./build/TESTS --gtest_filter=FileTests.AES_TEST_CTR_PKCS7
perf script > perf.unfold
/usr/bin/stackcollapse-perf.pl perf.unfold > perf.folded
/usr/bin/flamegraph.pl perf.folded > flamegraph.svg
firefox flamegraph.svg
