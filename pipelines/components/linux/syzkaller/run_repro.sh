#!/bin/bash

OUTDIR=/shellphish/syzkaller/workdir/out/

mkdir $OUTDIR

for dir in /shellphish/syzkaller/workdir/crashes/*/     # list directories
do 
	dirname=`basename $dir`
	# find number of logs
	num_repros=`ls -l $dir | grep log | wc -l`
	echo "dirname: $dirname"
	mkdir $OUTDIR/$dirname
	i=0
	echo "Number of repros for $dir: $num_repros"
	while [ $i -lt $num_repros ];
	do
		echo "Trying log$i"
		bin/syz-repro -config=syzconfig.cfg $dir/log$i >$dir/out_$i.log 2>&1
		if test -f "repro.txt"; then
			echo "$dir/log$i was successful!"
			mv repro.txt $dir/repro$i.txt
			mv repro.c $dir/repro$i.c
			cp $dir/repro$i.txt $OUTDIR/$dirname/repro.txt
			cp $dir/repro$i.c $OUTDIR/$dirname/repro.c
			break
		fi
		((i++))
		sleep 2
	done
done
