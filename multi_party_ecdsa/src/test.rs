use super::*;
use crate::utilities::class_group::*;
use k256::Scalar;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use rand::rngs::OsRng;
use sha2::Digest;
use k256::ecdsa::{VerifyingKey, signature::Verifier}; 
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa::signature::Signature;
use bincode::config::standard;
use crate::shared::*;

#[test]
fn mta_test() {
    let a = Scalar::random(&mut OsRng);
    let b = Scalar::random(&mut OsRng);
    let group = CLGroup::new();
    let (cl_priv_key, cl_pub_key) = group.keygen();
    let mut mta_party_one = mta::PartyOne::new(a);
    let mut mta_party_two = mta::PartyTwo::new(b);
    let mta_msg = mta_party_one.generate_send_msg(&cl_pub_key);
    let mta_second_round_msg = mta_party_two
        .receive_and_send_msg(mta_msg)
        .unwrap();
    mta_party_one.handle_receive_msg(&cl_priv_key, &mta_second_round_msg);
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
    
    // Create public shares from the secret shares
    let party_one_public_share = k256::ProjectivePoint::GENERATOR * x1;
    let party_two_public_share = k256::ProjectivePoint::GENERATOR * x2;
    
    // Calculate the combined public key
    let public_signing_key = party_one_public_share + party_two_public_share;
    
    // Create KeyStore for both parties
    let party_one_key = KeyStore {
        secret_share: x1,
        public_share: party_one_public_share,
        public_signing_key,
    };
    
    let party_two_key = KeyStore {
        secret_share: x2,
        public_share: party_two_public_share,
        public_signing_key,
    };
    // println!("party_one_key = {:?}", party_one_key);
    // println!("party_two_key = {:?}", party_two_key);

    // sign begin
    let message = b"hello world";
    let message_hash = sha2::Sha256::digest(message).to_vec();
    
    let start_time = std::time::Instant::now();

    let mut party_one_sign = party_one::Sign::new(party_one_key).unwrap();
    let mut party_two_sign = party_two::Sign::new(party_two_key).unwrap();

    let party_two_nonce_com = party_two_sign.generate_nonce_com();

    // P1 -> P2: party_two_nonce_com 
    let party_two_nonce_com_serialized = bincode::serde::encode_to_vec(&party_two_nonce_com, standard()).unwrap();
    let (party_two_nonce_com_deserialized, _): (utilities::dl_com_zk::DLCommitments, usize) = 
        bincode::serde::decode_from_slice(&party_two_nonce_com_serialized, standard()).unwrap();

    party_one_sign.get_nonce_com(&party_two_nonce_com_deserialized);

    //mta begin;
    let group = CLGroup::new();
    let (cl_priv_key, cl_pub_key) = group.keygen();
    let mut mta_party_one =
        mta::PartyOne::new(party_one_sign.reshared_secret_share);
    let mut mta_party_two = mta::PartyTwo::new(party_two_sign.nonce_secret_share);

    let mta_first_round_msg = mta_party_one.generate_send_msg(&cl_pub_key);

    // P1 -> P2: mta_first_round_msg
    
    let mta_first_round_msg_serialized = bincode::serde::encode_to_vec(&mta_first_round_msg, standard()).unwrap();
    println!("mta_first_round_msg: {} bytes", mta_first_round_msg_serialized.len());
    let (mta_first_round_msg_deserialized, _): (utilities::cl_proof::MTAFirstRoundMsg, usize) = 
        bincode::serde::decode_from_slice(&mta_first_round_msg_serialized, standard()).unwrap();

    let mta_second_round_msg = mta_party_two
        .receive_and_send_msg(mta_first_round_msg_deserialized)
        .unwrap();

    // P2 -> P1: mta_second_round_msg
    let mta_second_round_msg_serialized = bincode::serde::encode_to_vec(&mta_second_round_msg, standard()).unwrap();
    println!("mta_second_round_msg: {} bytes", mta_second_round_msg_serialized.len());
    let (mta_second_round_msg_deserialized, _): (utilities::class_group::Ciphertext, usize) = 
        bincode::serde::decode_from_slice(&mta_second_round_msg_serialized, standard()).unwrap();

    mta_party_one.handle_receive_msg(&cl_priv_key, &mta_second_round_msg_deserialized);
    let mta_consistency_msg = party_one_sign.generate_mta_consistency(mta_party_one.t_b);

    // P1 -> P2: mta_consistency_msg
    let mta_consistency_msg_serialized = bincode::serde::encode_to_vec(&mta_consistency_msg, standard()).unwrap();
    println!("mta_consistency_msg: {} bytes", mta_consistency_msg_serialized.len());
    let (mta_consistency_msg_deserialized, _): (MtaConsistencyMsg, usize) = 
        bincode::serde::decode_from_slice(&mta_consistency_msg_serialized, standard()).unwrap();

    party_two_sign
        .verify_generate_mta_consistency(mta_party_two.t_a, &mta_consistency_msg_deserialized)
        .unwrap();

    let party_one_nonce_ke_msg = party_one_sign.generate_nonce_ke_msg();

    // P1 -> P2: party_one_nonce_ke_msg
    let party_one_nonce_ke_msg_serialized = bincode::serde::encode_to_vec(&party_one_nonce_ke_msg, standard()).unwrap();
    println!("party_one_nonce_ke_msg: {} bytes", party_one_nonce_ke_msg_serialized.len());
    let (party_one_nonce_ke_msg_deserialized, _): (NonceKEMsg, usize) = 
        bincode::serde::decode_from_slice(&party_one_nonce_ke_msg_serialized, standard()).unwrap();

    let party_two_nonce_ke_msg = party_two_sign
        .verify_send_nonce_ke_msg(&party_one_nonce_ke_msg_deserialized)
        .unwrap();

    // P2 -> P1: party_two_nonce_ke_msg
    let party_two_nonce_ke_msg_serialized = bincode::serde::encode_to_vec(&party_two_nonce_ke_msg, standard()).unwrap();
    println!("party_two_nonce_ke_msg: {} bytes", party_two_nonce_ke_msg_serialized.len());
    let (party_two_nonce_ke_msg_deserialized, _): (utilities::dl_com_zk::CommWitness, usize) = 
        bincode::serde::decode_from_slice(&party_two_nonce_ke_msg_serialized, standard()).unwrap();

    party_one_sign
        .verify_nonce_ke_msg(&party_two_nonce_ke_msg_deserialized)
        .unwrap();

    let s_2 = party_two_sign.online_sign(&message_hash);

    // P2 -> P1: s_2
    let s_2_serialized = bincode::serde::encode_to_vec(&s_2, standard()).unwrap();
    println!("s_2: {} bytes", s_2_serialized.len());
    let (s_2_deserialized, _): (Scalar, usize) = 
        bincode::serde::decode_from_slice(&s_2_serialized, standard()).unwrap();

    let signature = party_one_sign.online_sign(&s_2_deserialized, &message_hash).unwrap();

    let elapsed_time = start_time.elapsed();
    println!("Signing time: {} ms", elapsed_time.as_millis());
    
    // Convert our r,s to k256 signature format
    let r = signature.r.to_bytes().to_vec();
    let s = signature.s.to_bytes().to_vec();
    let signature = [r, s].concat();

    println!("Signature (hex): {}", hex::encode(&signature));
    
    let k256_sig = k256::ecdsa::Signature::from_bytes(&signature).unwrap();
    
    // Get the public key in the right format
    let public_key_point = party_one_sign.key_store.public_signing_key;
    let affine = public_key_point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let verifying_key = VerifyingKey::from_sec1_bytes(encoded.as_bytes()).unwrap();
    println!("Public key (hex): {}", hex::encode(encoded.as_bytes()));
    
    // Verify signature with k256
    let k256_verify_result = verifying_key.verify(message, &k256_sig);
    println!("k256 native verification result: {:?}", k256_verify_result);
}
