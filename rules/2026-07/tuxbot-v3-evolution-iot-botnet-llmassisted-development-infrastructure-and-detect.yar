import "hash"
rule TuxBot_v3_Evolution {
    meta:
        author = "DetectHQ by GanaSec"
        reference = "https://detecthq.in"
        date = "2026-07-15"
        description = "Detects TuxBot v3 Evolution IoT botnet binaries"
    strings:
        $banner = "Infected By Akiru"
    condition:
        any of (
            hash.sha256(0, filesize) == "0f8bcca3ed65e980da2a1f90a767b7d543be32eeea3e9338d09d4d635a497988",
            hash.sha256(0, filesize) == "146f6010f6ee082aab13e0148d39baefa77eaba4ff65817b511b08c2092bdfd2",
            hash.sha256(0, filesize) == "246c97957651de568e61eba1abe572f0b0f960456209995d43d53a0d7cc494a1",
            hash.sha256(0, filesize) == "2f2c3551762c03da126e45dca6fc2f997c63f0f1bfc21fd0ceed680ac6f083ce",
            hash.sha256(0, filesize) == "3ec016d637e4c9cd331edd2580a229621ad638e924a4aa29ac0342e9144ace19",
            hash.sha256(0, filesize) == "6b7a8e0c96c2318e747f074f9a99d26738700769ac01bba692d19fc884847737",
            hash.sha256(0, filesize) == "71dfbb171eca4ef9d02ff630b56e5283bbef7b375d4dbe9e8c9531bef312fa8d",
            hash.sha256(0, filesize) == "96b1f96efca3b9df2dea85678d60da27e3265b4a00e39e20e64b27bb985e1561",
            $banner
        )
}