tiny:
	analyzer -debug-verbose 1 -dump-leakers \
    `find ../kernels/tinytest-linux/ -name "*\.bc"` \
    2>./out/tiny/latest

all:
	nohup analyzer -debug-verbose 0 -dump-leakers \
    `find ../kernels/linux-5.5.3-allyes-ir/ -name "*\.bc"` \
    2>./out/all/latest &

def:
	nohup analyzer -debug-verbose 0 -analyze-leakers \
    `find ../kernels/linux-5.5.3-def-ir/ -name "*\.bc"` \
    2>./out/cnstrall/latest &

defdebug:
	nohup analyzer -debug-verbose 0 -dump-leakers -check-leakers \
    `find ../kernels/linux-5.5.3-def-ir-debug/ -name "*\.ll"` \
    2>./out/defdebug/latest &

xnu:
	nohup analyzer -debug-verbose 0 -dump-leakers -check-leakers \
    `find ../kernels/xnu-4906.241.1/ -name "*\.ll"` \
    2>./out/xnu/latest &

xnutest:
	nohup analyzer -debug-verbose 0 -dump-leakers -check-leakers \
    `find ../kernels/xnu-test/ -name "*\.bc"` \
    2>./out/xnutest/latest &
