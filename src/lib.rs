pub mod quote;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::quote::{verify_quote, EnclaveIdentityRoot, parse_pem};
    use crate::types::quote::{SgxQuote, SgxEnclaveReport};
    use crate::types::tcbinfo::TcbInfoV2;
    use x509_parser::prelude::*;


    #[test]
    fn test_enclave_report() {
        let _pce_cert_bytes= hex::decode("308204f330820499a003020102021500d9ea43e27a3a7f24f43041256709c77ade109cb8300a06082a8648ce3d04030230703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553301e170d3232313132383232303231305a170d3239313132383232303231305a30703122302006035504030c19496e74656c205347582050434b204365727469666963617465311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000429830139411135adff259c51e79415f325dbc9d9d4e6672825d0a16b0a667a19548cf18a17dba627cbdf37efa08526e5f1132f3af5fcaf327485a06198e95c3da382030e3082030a301f0603551d23041830168014956f5dcdbd1be1e94049c9d4f433ce01570bde54306b0603551d1f046430623060a05ea05c865a68747470733a2f2f6170692e7472757374656473657276696365732e696e74656c2e636f6d2f7367782f63657274696669636174696f6e2f76332f70636b63726c3f63613d706c6174666f726d26656e636f64696e673d646572301d0603551d0e0416041400139ef2bb85ccc9f34e9ae2aa9cf9a5583c2311300e0603551d0f0101ff0404030206c0300c0603551d130101ff040230003082023b06092a864886f84d010d010482022c30820228301e060a2a864886f84d010d01010410442b0c77c7ccd6778264a287b7299bdb30820165060a2a864886f84d010d0102308201553010060b2a864886f84d010d0102010201073010060b2a864886f84d010d0102020201093010060b2a864886f84d010d0102030201033010060b2a864886f84d010d0102040201033011060b2a864886f84d010d010205020200ff3011060b2a864886f84d010d010206020200ff3010060b2a864886f84d010d0102070201013010060b2a864886f84d010d0102080201003010060b2a864886f84d010d0102090201003010060b2a864886f84d010d01020a0201003010060b2a864886f84d010d01020b0201003010060b2a864886f84d010d01020c0201003010060b2a864886f84d010d01020d0201003010060b2a864886f84d010d01020e0201003010060b2a864886f84d010d01020f0201003010060b2a864886f84d010d0102100201003010060b2a864886f84d010d01021102010d301f060b2a864886f84d010d010212041007090303ffff010000000000000000003010060a2a864886f84d010d0103040200003014060a2a864886f84d010d0104040600606a000000300f060a2a864886f84d010d01050a0101301e060a2a864886f84d010d0106041071865d4db8801ba66b0357f0bed771f13044060a2a864886f84d010d010730363010060b2a864886f84d010d0107010101ff3010060b2a864886f84d010d0107020101003010060b2a864886f84d010d010703010100300a06082a8648ce3d0403020348003045022100b925ce46afd79e24a0fd66437697f0077aa0caba8834d443922faa1b5494cfa302206c9f162b379fc94c706da45056bba116fa3a4fd4c9cf09382689168069c3c9b2").unwrap();
        let enclave_report_bytes =  vec![8, 9, 14, 13, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 0, 206, 29, 168, 154, 193, 245, 74, 128, 114, 87, 196, 229, 124, 120, 20, 12, 188, 102, 82, 212, 213, 135, 214, 15, 5, 131, 18, 90, 39, 146, 190, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86, 172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 188, 124, 79, 211, 205, 227, 97, 238, 49, 224, 32, 91, 56, 220, 72, 241, 138, 165, 234, 97, 86, 191, 147, 42, 38, 34, 143, 92, 197, 56, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        println!("enclave_report_bytes: {:?}", enclave_report_bytes.len());
        let enclave_report = SgxEnclaveReport::from_bytes(&enclave_report_bytes);
        println!("enclave_report: {:?}", enclave_report);
    }

    #[test]
    fn test_sgx_dcap_quote() {
        let root_cert_der= include_bytes!("../data/Intel_SGX_Provisioning_Certification_RootCA.cer");
        let (_, root_cert) = X509Certificate::from_der(root_cert_der).unwrap();

        let signing_cert_pem = include_bytes!("../data/signing_cert.pem");
        let signing_cert_pem = parse_pem(signing_cert_pem).unwrap();
        let signing_cert = signing_cert_pem[0].parse_x509().unwrap();

        let enclave_identity_root: EnclaveIdentityRoot = serde_json::from_str(include_str!("../data/qeidentity.json")).unwrap();

        let current_time = chrono::Utc::now().timestamp() as u64;

        let json_str = include_str!("../data/tcbinfo.json");
        let tcb_info_root: TcbInfoV2 = serde_json::from_str(json_str).unwrap();
        let dcap_quote_bytes = hex::decode("03000200000000000a000f00939a7233f79c4ca9940a0db3957f0607ce48836fd48a951172fe155220a719bd0000000014140207018001000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000700000000000000dc43f8c42d8e5f52c8bbd68f426242153f0be10630ff8cca255129a3ca03d27300000000000000000000000000000000000000000000000000000000000000001cf2e52911410fbf3f199056a98d58795a559a2e800933f7fcd13d048462271c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009113b0be77ed5d0d68680ec77206b8d587ed40679b71321ccdd5405e4d54a682000000000000000000000000000000000000000000000000000000000000000044100000d6be1afe26464a3eeb6d5ade46b24ab38ad339821cacc9a923e2e3335e73fab8a89617a1ada00d4c8a0e1ff2315ede22c49a98bc83907056ce6121c1b10d2e3abe6177e039634cfbca4739ac246fda7df8c312a98f30f57b63f3c8921fce51d90a93031f97f769637be9b028e7b007a4e458d4fa717befbd81b06905082580131414020701800100000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000070000000000000096b347a64e5a045e27369c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e400000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b0f056c5355f6c770413938c2a41ed1b5c34ecb35f85fa539f16cca7a30d6da90000000000000000000000000000000000000000000000000000000000000000a67269ee80d0dfc26e9bbcf5525ec6a7bf3f4a4092e0a6dd1bf2053962dbb49c59af50a49e784ea3c7e57cd669a9c0e6bc51e04dcc5582393c6393168846cf7e2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500dc0d00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949456a544343424453674177494241674956414a5172493559365a78484836785034424941715a4e6b326e4c7a594d416f4743437147534d343942414d430a4d484578497a416842674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a4165467730794d7a45784d5441784e7a45334d4452614677307a4d4445784d5441784e7a45330a4d4452614d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675132567964476c6d61574e6864475578476a415942674e560a42416f4d45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b470a413155454341774351304578437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741450a77625468574d583134443163657835317875614958456771517a69636e744b7a48454a32536f31336e384a427050314a67383673764263462f7070715a554e710a68524b4642667469584c6d4f536c614955784e6e51364f434171677767674b6b4d42384741315564497751594d426141464e446f71747031312f6b75535265590a504873555a644456386c6c4e4d477747413155644877526c4d474d77596142666f463247573268306448427a4f693876595842704c6e527964584e305a57527a0a5a584a3261574e6c63793570626e526c6243356a62323076633264344c324e6c636e52705a6d6c6a5958527062323476646a517663474e7259334a7350324e680a5058427962324e6c63334e7663695a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464a57566e41395a63736f3753356b6a2f647a4a0a594f3034534175644d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949423141594a4b6f5a496876684e0a415130424249494278544343416345774867594b4b6f5a496876684e41513042415151514d6d5867725757774c59554164456d6c766c366153444343415751470a43697147534962345451454e41514977676746554d42414743797147534962345451454e41514942416745554d42414743797147534962345451454e415149430a416745554d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745454d42414743797147534962340a5451454e41514946416745424d42454743797147534962345451454e41514947416749416744415142677371686b69472b4530424451454342774942414441510a42677371686b69472b45304244514543434149424144415142677371686b69472b45304244514543435149424144415142677371686b69472b453042445145430a436749424144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69470a2b45304244514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b4530424451454344774942414441510a42677371686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b453042445145430a4567515146425143424147414141414141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b4530420a44514545424159416b473668414141774477594b4b6f5a496876684e4151304242516f424144414b42676771686b6a4f5051514441674e4841444245416942560a6e584667364277466a6945474230417162424e702b4b56734a477245744f4f49666e6f365450387031414967536c4430574e39595261575968346534656835330a314637434537664964724f55414c5177757632735948513d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436d444343416a36674177494241674956414e446f71747031312f6b7553526559504873555a644456386c6c4e4d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484578497a41680a42674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b4442464a626e526c0a6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e420a4d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424c39712b4e4d7032494f670a74646c31626b2f75575a352b5447516d38614369387a373866732b664b435133642b75447a586e56544154325a68444369667949754a77764e33774e427039690a484253534d4a4d4a72424f6a6762737767626777487759445652306a42426777466f4155496d554d316c71644e496e7a6737535655723951477a6b6e427177770a556759445652306642457377535442486f45576751345a426148523063484d364c79396a5a584a3061575a70593246305a584d7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253394a626e526c62464e4857464a76623352445153356b5a584977485159445652304f42425945464e446f0a71747031312f6b7553526559504873555a644456386c6c4e4d41344741315564447745422f77514541774942426a415342674e5648524d4241663845434441470a4151482f416745414d416f4743437147534d343942414d43413067414d4555434951434a6754627456714f795a316d336a716941584d365159613672357357530a34792f4737793875494a4778647749675271507642534b7a7a516167424c517135733541373070646f6961524a387a2f3075447a344e675639316b3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00").unwrap();
        let dcap_quote = SgxQuote::from_bytes(&dcap_quote_bytes);
        println!("dcap_quote: {:?}", dcap_quote);
        verify_quote(&dcap_quote, &tcb_info_root, &enclave_identity_root,&signing_cert, &root_cert, current_time);
    }
}
