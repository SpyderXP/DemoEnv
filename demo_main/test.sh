#!/bin/bash

check_all_md5()
{
    # awk 'NR == 1 { print $1 }' all.md5

    if [ -f ./all.md5 ]; then
        while read md5line
        do
            namestr=$(echo "$md5line" | awk '{ print $1 }')
            md5str=$(echo "$md5line" | awk '{ print $2 }')

            if [ "$namestr" = "CPU" ]; then
                echo "CPU md5: $md5str"
                sed -i "/^$namestr/ s/$md5str/3333333/" all.md5
            elif [ "$namestr" = "FPGA" ]; then
                echo "FPGA md5: $md5str"
            else
                echo "Unknown md5"
            fi
        done < all.md5
    else
        touch all.md5
        cpumd5str=`md5sum a.txt`
        echo -e "CPU\t$cpumd5str" >> all.md5
    fi
}

# check_all_md5

sig_size=`ls -l sig.pem | awk '{ print $5 }'`
printf "%08x" $sig_size | xxd -r -p > size.txt
cat size.txt sig.pem data.txt > final.img

echo "Over"
