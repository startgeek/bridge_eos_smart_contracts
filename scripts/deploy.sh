#cleos wallet unlock --password XXXXXXXXXXXXXXXXXXXX...

#in another shell:
#rm -rf ~/.local/share/eosio/nodeos/data
#nodeos -e -p eosio --plugin eosio::chain_api_plugin --plugin eosio::history_api_plugin --contracts-console --verbose-http-errors

set -x

PUBLIC_KEY=EOS5CYr5DvRPZvfpsUGrQ2SnHeywQn66iSbKKXn4JDTbFFr36TRTX
EOSIO_DEV_KEY=EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV

cleos create account eosio bridge $PUBLIC_KEY
cleos set contract bridge . Bridge.wasm --abi Bridge.abi -p bridge@active

cleos push action bridge storeroots '{
"epoch_num_vec":[0,156],
"root_vec": [0x55,0xb8,0x91,0xe8,0x42,0xe5,0x8f,0x58,0x95,0x6a,0x84,0x7c,0xbb,0xf6,0x78,0x21,
	         0xd0,0xeb,0x4a,0x9f,0xf0,0xdc,0x08,0xa9,0x14,0x9b,0x27,0x5e,0x3a,0x64,0xe9,0x3d]
}' -p bridge@active
