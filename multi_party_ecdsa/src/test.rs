use super::*;
use crate::utilities::class_group::*;
use crate::utilities::clkeypair::ClKeyPair;
use k256::Scalar;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use rand::rngs::OsRng;
use sha2::Digest;
use k256::ecdsa::{VerifyingKey, signature::Verifier}; 
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa::signature::Signature;

#[test]
fn mta_test() {
    let a = Scalar::random(&mut OsRng);
    let b = Scalar::random(&mut OsRng);
    let cl_keypair = ClKeyPair::new(&GROUP_128);
    let mut mta_party_one = mta::PartyOne::new(a);
    let mut mta_party_two = mta::PartyTwo::new(b);
    let mta_first_round_msg = mta_party_one.generate_send_msg(&cl_keypair.cl_pub_key);
    let mta_second_round_msg = mta_party_two
        .receive_and_send_msg(mta_first_round_msg.0, mta_first_round_msg.1)
        .unwrap();
    mta_party_one.handle_receive_msg(&cl_keypair.cl_priv_key, &mta_second_round_msg);
    assert_eq!(a * b, mta_party_two.t_a + mta_party_one.t_b);
}
#[test]
fn party_two_test() {
    // Import secret key
    let secret_key_bytes = hex::decode("1e99423a4edf5c3d3f8b1c0e8f7f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5").unwrap();
    
    // Convert bytes to Scalar
    let mut sk_array = [0u8; 32];
    sk_array.copy_from_slice(&secret_key_bytes);
    let secret_key = Scalar::from_repr(sk_array.into()).unwrap();
    
    // Split secret key into two shares: x1 and x2 where x1 + x2 = secret_key
    let x1 = Scalar::random(&mut OsRng);  // party_one's share
    let x2 = secret_key - x1;              // party_two's share
    
    // Create keypairs from the shares
    let party_one_keypair = crate::utilities::eckeypair::EcKeyPair::from_sk(x1);
    let party_two_keypair = crate::utilities::eckeypair::EcKeyPair::from_sk(x2);
    
    // Calculate the combined public key
    let public_signing_key = party_one_keypair.public_share + party_two_keypair.public_share;
    
    // Create KeyGenResult for both parties
    let party_one_key = party_one::KeyGenResult {
        keypair: party_one_keypair.clone(),
        public_signing_key,
    };
    
    let party_two_key = party_two::KeyGenResult {
        keypair: party_two_keypair.clone(),
        public_signing_key,
        other_public_key: party_one_keypair.public_share,
    };
    // println!("party_one_key = {:?}", party_one_key);
    // println!("party_two_key = {:?}", party_two_key);

    // sign begin
    let message = b"hello world";
    let message_hash = sha2::Sha256::digest(message).to_vec();
    
    let mut party_one_sign = party_one::Sign::new(&message_hash, false).unwrap();
    let mut party_two_sign = party_two::Sign::new(&message_hash, false).unwrap();
    party_one_sign.keygen_result = Some(party_one_key);
    party_two_sign.keygen_result = Some(party_two_key);
    let party_two_nonce_com = party_two_sign.generate_nonce_com();
    party_one_sign.get_nonce_com(&party_two_nonce_com);

    //mta begin;
    let cl_keypair = ClKeyPair::new(&GROUP_128);
    let mut mta_party_one =
        mta::PartyOne::new(party_one_sign.reshared_keypair.secret_share);
    let mut mta_party_two = mta::PartyTwo::new(party_two_sign.nonce_pair.secret_share);

    let mta_first_round_msg = mta_party_one.generate_send_msg(&cl_keypair.cl_pub_key);
    let mta_second_round_msg = mta_party_two
        .receive_and_send_msg(mta_first_round_msg.0, mta_first_round_msg.1)
        .unwrap();
    mta_party_one.handle_receive_msg(&cl_keypair.cl_priv_key, &mta_second_round_msg);
    let mta_consistency_msg = party_one_sign.generate_mta_consistency(mta_party_one.t_b);

    party_two_sign
        .verify_generate_mta_consistency(mta_party_two.t_a, &mta_consistency_msg)
        .unwrap();

    let party_one_nonce_ke_msg = party_one_sign.generate_nonce_ke_msg();

    let party_two_nonce_ke_msg = party_two_sign
        .verify_send_nonce_ke_msg(&party_one_nonce_ke_msg)
        .unwrap();

    party_one_sign
        .verify_nonce_ke_msg(&party_two_nonce_ke_msg)
        .unwrap();

    let s_2 = party_two_sign.online_sign();

    let signature = party_one_sign.online_sign(&s_2).unwrap();
    
    // Convert our r,s to k256 signature format
    let r = signature.r.to_bytes().to_vec();
    let s = signature.s.to_bytes().to_vec();
    let signature = [r, s].concat();

    println!("Signature (hex): {}", hex::encode(&signature));
    
    let k256_sig = k256::ecdsa::Signature::from_bytes(&signature).unwrap();
    
    // Get the public key in the right format
    let public_key_point = party_one_sign.keygen_result.as_ref().unwrap().public_signing_key;
    let affine = public_key_point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let verifying_key = VerifyingKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
    println!("Public key (hex): {}", hex::encode(encoded.as_bytes()));
    
    // Verify signature with k256
    let k256_verify_result = verifying_key.verify(message, &k256_sig);
    println!("k256 native verification result: {:?}", k256_verify_result);
}

