//! keri.process through the host (src/kel.rs), on KERI 1.x streams devrandom itself builds
//! (tests/support). Each test states what devrandom decides and checks that the adapter reports
//! it, and that the host's composed behaviours (routing, escrow, delegation evidence, superseding
//! rewind, duplicity, receipt attachment) feed the library what it needs.

mod support;

use keri::Custodian;

use support::*;

#[test]
fn an_inception_is_seen_on_the_trunk_and_reported_as_key_state() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let result = process(&[alice.frame(&icp)]);
    assert_eq!(readings(&result), [r("seen", "seen", true)]);
    let state = &result["key_states"][alice.prefix()];
    assert_eq!(state["sn"], 0);
    assert_eq!(state["said"], icp.said().to_qb64());
    assert_eq!(state["keys"][0], alice.commitment.verkeys[0].to_qb64());
    assert_eq!(state["kt"], "1");
    assert_eq!(state["ndigs"][0], alice.commitment.next_digests[0].to_qb64());
    assert_eq!(state["nt"], "1");
    assert_eq!(state["wits"], serde_json::json!([]));
    assert_eq!(state["bt"], "0");
    assert_eq!(state["delegator"], serde_json::Value::Null);
}

#[test]
fn rotation_and_interaction_advance_the_kel() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let icp_wire = alice.frame(&icp);
    let rot = alice.rot(false, vec![]);
    let rot_wire = alice.frame(&rot);
    let ixn = alice.ixn(vec![]);
    let result = process(&[icp_wire, rot_wire, alice.frame(&ixn)]);
    assert_eq!(readings(&result), vec![r("seen", "seen", true); 3]);
    assert_eq!(result["key_states"][alice.prefix()]["sn"], 2);
    assert_eq!(result["key_states"][alice.prefix()]["said"], ixn.said().to_qb64());
}

fn reason(result: &serde_json::Value, index: usize) -> String {
    result["dispositions"][index]["reason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[test]
fn an_event_signed_by_the_wrong_keys_is_rejected() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let (mallory, _) = Controller::incept(2, Options::default());
    let forged = frame(&icp, &mallory.sigs(&icp), &[]);
    let result = process(&[forged]);
    assert_eq!(readings(&result), [r("rejected", "rejected", false)]);
    assert!(reason(&result, 0).contains("MissingSignatures"), "{result}");
    assert!(result["key_states"].get(alice.prefix()).is_none());
}

#[test]
fn an_event_for_an_unknown_identifier_is_held_until_its_inception_arrives() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let icp_wire = alice.frame(&icp);
    let ixn = alice.ixn(vec![]);
    let result = process(&[alice.frame(&ixn), icp_wire]);
    assert_eq!(
        readings(&result),
        [r("pending", "seen", true), r("seen", "seen", true)]
    );
}

#[test]
fn an_event_past_the_next_sequence_number_waits_for_the_ones_before_it() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let ixn1 = alice.ixn(vec![]);
    let ixn2 = alice.ixn(vec![]);
    let result = process(&[alice.frame(&icp), alice.frame(&ixn2), alice.frame(&ixn1)]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("pending", "seen", true),
            r("seen", "seen", true)
        ]
    );
    assert!(reason(&result, 1).is_empty());
    assert_eq!(result["key_states"][alice.prefix()]["sn"], 2);
}

#[test]
fn a_second_delivery_of_a_seen_event_is_still_seen() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let result = process(&[alice.frame(&icp), alice.frame(&icp)]);
    assert_eq!(readings(&result), vec![r("seen", "seen", true); 2]);
}

#[test]
fn a_conflicting_interaction_is_duplicitous_and_off_the_trunk() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let (mut twin, _) = Controller::incept(1, Options::default());
    let ixn = alice.ixn(vec![]);
    let other = twin.ixn(vec![alice.seal()]);
    let result = process(&[alice.frame(&icp), alice.frame(&ixn), twin.frame(&other)]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("seen", "seen", true),
            r("duplicitous", "duplicitous", false)
        ]
    );
    assert!(reason(&result, 2).contains(&ixn.said().to_qb64()), "{result}");
}

#[test]
fn a_rotation_supersedes_an_interaction_which_stays_seen_off_the_trunk() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let (mut twin, _) = Controller::incept(1, Options::default());
    let ixn = alice.ixn(vec![]);
    let ixn2 = alice.ixn(vec![]);
    let rot = twin.rot(false, vec![]);
    let rot_wire = twin.frame(&rot);
    let result = process(&[
        alice.frame(&icp),
        alice.frame(&ixn),
        alice.frame(&ixn2),
        rot_wire,
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("seen", "seen", false),
            r("seen", "seen", false),
            r("seen", "seen", true)
        ]
    );
    assert_eq!(reason(&result, 3), "superseding rotation");
    assert_eq!(result["key_states"][alice.prefix()]["said"], rot.said().to_qb64());
}

#[test]
fn a_rotation_that_cannot_supersede_a_rotation_is_refused() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let icp_wire = alice.frame(&icp);
    let (mut twin, _) = Controller::incept(1, Options::default());
    let rot = alice.rot(false, vec![]);
    let rot_wire = alice.frame(&rot);
    let other = twin.rot(false, vec![alice.seal()]);
    let result = process(&[icp_wire, rot_wire, twin.frame(&other)]);
    let last = &readings(&result)[2];
    assert_ne!(last.1, "seen", "{result}");
    assert!(!last.2);
}

#[test]
fn a_superseding_rotation_that_fails_its_own_checks_is_rejected() {
    let (mut alice, icp) = Controller::incept(1, Options::default());
    let (mut twin, _) = Controller::incept(1, Options::default());
    let (mallory, _) = Controller::incept(9, Options::default());
    let ixn = alice.ixn(vec![]);
    let rot = twin.rot(false, vec![]);
    let forged = frame(&rot, &mallory.sigs(&rot), &[]);
    let result = process(&[alice.frame(&icp), alice.frame(&ixn), forged]);
    assert_eq!(readings(&result)[2], r("rejected", "rejected", false));
    assert_eq!(readings(&result)[1], r("seen", "seen", true));
}

#[test]
fn signatures_delivered_separately_are_combined_until_the_threshold_is_met() {
    let options = || Options {
        spec: spec(2, 2),
        threshold: Some(keri_events::SigningThreshold::Simple(2)),
        ..Options::default()
    };
    let (alice, icp) = Controller::incept(1, options());
    let sigs = alice.sigs(&icp);
    let result = process(&[
        frame(&icp, &sigs[..1], &[]),
        frame(&icp, &sigs[1..], &[]),
    ]);
    assert_eq!(
        readings(&result),
        [r("pending", "seen", true), r("seen", "seen", true)]
    );
    assert!(result["dispositions"][0].get("reason").is_none());
    let partial = process(&[frame(&icp, &sigs[..1], &[])]);
    assert!(reason(&partial, 0).contains("awaiting Signatures"), "{partial}");
}

#[test]
fn weighted_thresholds_are_reported_as_fractions() {
    use keri_events::SigningThreshold;
    use keri_events::threshold::WeightedThreshold;
    let one = WeightedThreshold::from_nested(vec![vec![(1, 2), (1, 2)]]).unwrap();
    let (alice, icp) = Controller::incept(
        1,
        Options {
            spec: spec(2, 2),
            threshold: Some(SigningThreshold::Weighted(one)),
            ..Options::default()
        },
    );
    let result = process(&[alice.frame(&icp)]);
    assert_eq!(readings(&result), [r("seen", "seen", true)]);
    assert_eq!(
        result["key_states"][alice.prefix()]["kt"],
        serde_json::json!(["1/2", "1/2"])
    );
    let two = WeightedThreshold::from_nested(vec![vec![(1, 1)], vec![(1, 2), (1, 2)]]).unwrap();
    assert_eq!(
        kcs_adapter_devrandom::kel::threshold(&SigningThreshold::Weighted(two)),
        serde_json::json!([["1"], ["1/2", "1/2"]])
    );
}

fn delegated() -> (Controller, Controller, keri_codec::SerializedEvent, keri_codec::SerializedEvent) {
    let (delegator, dicp) = Controller::incept(1, Options::default());
    let (delegate, dip) = Controller::incept(
        2,
        Options {
            delegator: Some(delegator.id.clone()),
            ..Options::default()
        },
    );
    (delegator, delegate, dicp, dip)
}

#[test]
fn a_delegated_inception_waits_for_its_anchor_and_names_its_delegator() {
    let (mut delegator, delegate, dicp, dip) = delegated();
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let result = process(&[
        delegator.frame(&dicp),
        delegate.frame(&dip),
        delegator.frame(&anchor),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("pending", "seen", true),
            r("seen", "seen", true)
        ]
    );
    assert_eq!(
        result["key_states"][delegate.prefix()]["delegator"],
        delegator.prefix()
    );
}

#[test]
fn a_delegated_inception_with_no_delegator_kel_waits() {
    let (_, delegate, _, dip) = delegated();
    let result = process(&[delegate.frame(&dip)]);
    assert_eq!(readings(&result), [r("pending", "pending", false)]);
    assert!(reason(&result, 0).contains("awaiting DelegationEvidence"), "{result}");
}

#[test]
fn a_seal_source_couple_names_the_anchor_and_is_read_by_the_second_reading() {
    let (mut delegator, delegate, dicp, dip) = delegated();
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let with_seal = bare(
        &dip,
        &[sig_group(&delegate.sigs(&dip)), seal_group(1, &anchor.said().to_qb64())],
    );
    let result = process(&[delegator.frame(&dicp), with_seal.clone(), delegator.frame(&anchor)]);
    assert_eq!(readings(&result)[1], r("pending", "seen", true));
    // A couple naming an event the delegator's KEL does not hold at that sn keeps it held.
    let wrong = bare(
        &dip,
        &[sig_group(&delegate.sigs(&dip)), seal_group(1, &dicp.said().to_qb64())],
    );
    let result = process(&[delegator.frame(&dicp), wrong, delegator.frame(&anchor)]);
    assert_eq!(readings(&result)[1], r("pending", "pending", false));
}

#[test]
fn a_delegated_rotation_is_judged_with_its_anchor() {
    let (mut delegator, mut delegate, dicp, dip) = delegated();
    let dip_wire = delegate.frame(&dip);
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let drt = delegate.rot(true, vec![]);
    let drt_wire = delegate.frame(&drt);
    let anchor2 = delegator.ixn(vec![delegate.seal()]);
    let result = process(&[
        delegator.frame(&dicp),
        delegator.frame(&anchor),
        dip_wire,
        drt_wire,
        delegator.frame(&anchor2),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("seen", "seen", true),
            r("seen", "seen", true),
            r("pending", "seen", true),
            r("seen", "seen", true)
        ]
    );
    assert_eq!(result["key_states"][delegate.prefix()]["sn"], 1);
}

#[test]
fn a_delegated_rotation_supersedes_an_interaction_with_its_anchor() {
    let (mut delegator, mut delegate, dicp, dip) = delegated();
    let dip_wire = delegate.frame(&dip);
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let (mut twin, _) = Controller::incept(
        2,
        Options {
            delegator: Some(delegator.id.clone()),
            ..Options::default()
        },
    );
    let ixn = delegate.ixn(vec![]);
    let drt = twin.rot(true, vec![]);
    let drt_wire = twin.frame(&drt);
    let anchor2 = delegator.ixn(vec![twin.seal()]);
    let result = process(&[
        delegator.frame(&dicp),
        delegator.frame(&anchor),
        dip_wire,
        delegate.frame(&ixn),
        delegator.frame(&anchor2),
        drt_wire,
    ]);
    let readings = readings(&result);
    assert_eq!(readings[3], r("seen", "seen", false), "{result}");
    assert_eq!(readings[5], r("seen", "seen", true), "{result}");
}

#[test]
fn delegated_rotations_contesting_each_other_are_judged_with_both_anchors() {
    let (mut delegator, mut delegate, dicp, dip) = delegated();
    let dip_wire = delegate.frame(&dip);
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let (mut twin, _) = Controller::incept(
        2,
        Options {
            delegator: Some(delegator.id.clone()),
            ..Options::default()
        },
    );
    let drt = delegate.rot(true, vec![]);
    let drt_wire = delegate.frame(&drt);
    let anchor2 = delegator.ixn(vec![delegate.seal()]);
    let other = twin.rot(true, vec![delegate.seal()]);
    let other_wire = twin.frame(&other);
    let anchor3 = delegator.ixn(vec![twin.seal()]);
    let delegator_events = [delegator.frame(&dicp), delegator.frame(&anchor)];
    let mut messages = delegator_events.to_vec();
    messages.extend([dip_wire, delegator.frame(&anchor2), drt_wire]);
    let mut anchored_first = messages.clone();
    anchored_first.extend([delegator.frame(&anchor3), other_wire.clone()]);
    let result = process(&anchored_first);
    // The rotation whose delegating event is later in the delegator's KEL supersedes.
    assert_eq!(readings(&result)[4], r("seen", "seen", false), "{result}");
    assert_eq!(readings(&result)[6], r("seen", "seen", true), "{result}");
    assert_eq!(reason(&result, 6), "superseding rotation");
    // Delivered before its anchor, the challenger cannot be judged yet, and is held until it is.
    let mut anchor_last = messages;
    anchor_last.extend([other_wire, delegator.frame(&anchor3)]);
    let result = process(&anchor_last);
    assert_eq!(readings(&result)[5], r("pending", "seen", true), "{result}");
    assert_eq!(readings(&result)[4], r("seen", "seen", false), "{result}");
}

#[test]
fn a_plain_rotation_on_a_delegated_kel_and_a_delegated_rotation_on_a_plain_one_are_refused() {
    let (mut delegator, mut delegate, dicp, dip) = delegated();
    let dip_wire = delegate.frame(&dip);
    let anchor = delegator.ixn(vec![delegate.seal()]);
    let rot = delegate.rot(false, vec![]);
    let result = process(&[
        delegator.frame(&dicp),
        delegator.frame(&anchor),
        dip_wire,
        delegate.frame(&rot),
    ]);
    assert_eq!(readings(&result)[3], r("rejected", "rejected", false));

    let (mut alice, icp) = Controller::incept(5, Options::default());
    let icp_wire = alice.frame(&icp);
    let drt = alice.rot(true, vec![]);
    let result = process(&[icp_wire, alice.frame(&drt)]);
    assert_eq!(readings(&result)[1], r("rejected", "rejected", false));
}

#[test]
fn a_first_seen_replay_couple_is_dropped() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let replayed = bare(&icp, &[sig_group(&alice.sigs(&icp)), first_seen_group(0)]);
    let result = process(&[replayed]);
    assert_eq!(readings(&result), [r("seen", "seen", true)]);
}

#[test]
fn the_second_reading_refuses_what_the_message_layer_would() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let sigs = sig_group(&alice.sigs(&icp));
    let w = Witness::new(30);
    let cases = [
        // A group no key event carries.
        bare(&icp, &[sigs.clone(), first_seen_group(0), couple_group(&w, icp.as_bytes())]),
        // A second message after the first.
        [bare(&icp, &[sigs.clone(), first_seen_group(0)]), alice.frame(&icp)].concat(),
        // A group that ends early.
        {
            let mut s = bare(&icp, &[sigs.clone(), first_seen_group(0)]);
            s.truncate(s.len() - 3);
            s
        },
    ];
    for stream in cases {
        let result = process(&[stream]);
        assert_eq!(readings(&result), [r("rejected", "rejected", false)], "{result}");
        assert!(!reason(&result, 0).is_empty());
    }
}

#[test]
fn streams_that_are_not_one_key_event_or_receipt_are_rejected() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let cases = [
        [alice.frame(&icp), alice.frame(&icp)].concat(),
        b"not cesr".to_vec(),
        registry_inception(&alice),
    ];
    for stream in cases {
        let result = process(&[stream]);
        assert_eq!(readings(&result), [r("rejected", "rejected", false)], "{result}");
        assert!(!reason(&result, 0).is_empty());
    }
}

fn witnessed(seed: u8, witness: &Witness) -> (Controller, keri_codec::SerializedEvent) {
    Controller::incept(
        seed,
        Options {
            witnesses: vec![witness.prefix.clone()],
            toad: Some(1),
            ..Options::default()
        },
    )
}

#[test]
fn a_witnessed_inception_waits_for_a_receipt_couple_which_is_then_seen() {
    let w = Witness::new(30);
    let (alice, icp) = witnessed(1, &w);
    let rct = receipt(&alice.prefix(), 0, &icp.said().to_qb64(), &[couple_group(&w, icp.as_bytes())]);
    let result = process(&[alice.frame(&icp), rct]);
    assert_eq!(
        readings(&result),
        [r("pending", "seen", true), r("seen", "seen", false)]
    );
    assert!(reason(&result, 0).is_empty());
    assert_eq!(result["key_states"][alice.prefix()]["bt"], "1");
    assert_eq!(result["key_states"][alice.prefix()]["wits"][0], w.prefix.to_qb64());
}

#[test]
fn a_receipt_before_its_event_is_held_and_then_attached() {
    let w = Witness::new(30);
    let (alice, icp) = witnessed(1, &w);
    let rct = receipt(&alice.prefix(), 0, &icp.said().to_qb64(), &[wig_group(&[w.wig(icp.as_bytes(), 0)])]);
    let result = process(&[rct, alice.frame(&icp)]);
    assert_eq!(
        readings(&result),
        [r("pending", "seen", false), r("seen", "seen", true)]
    );
}

#[test]
fn an_inline_witness_signature_is_enough_and_late_receipts_are_judged() {
    let w = Witness::new(30);
    let (alice, icp) = witnessed(1, &w);
    let body = icp.as_bytes();
    let said = icp.said().to_qb64();
    let inline = frame(&icp, &alice.sigs(&icp), &[w.wig(body, 0)]);
    let other = Witness::new(31);
    let result = process(&[
        inline,
        receipt(&alice.prefix(), 0, &said, &[wig_group(&[w.wig(body, 0)])]),
        receipt(&alice.prefix(), 0, &said, &[couple_group(&w, body)]),
        receipt(&alice.prefix(), 0, &said, &[couple_group(&other, body)]),
        receipt(&alice.prefix(), 0, &said, &[wig_group(&[other.wig(body, 0)])]),
        receipt(&alice.prefix(), 0, &said, &[format!(
            "{}{}{}",
            count(cesr::core::counter::CounterCodeV1::NonTransReceiptCouples, 1),
            w.prefix.to_qb64(),
            other.cigar(body)
        )]),
        receipt(&alice.prefix(), 1, &said, &[wig_group(&[w.wig(body, 0)])]),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("seen", "seen", false),
            r("seen", "seen", false),
            r("seen", "seen", false),
            r("rejected", "rejected", false),
            r("rejected", "rejected", false),
            r("rejected", "rejected", false)
        ]
    );
}

#[test]
fn receipts_for_a_held_event_are_verified_before_they_are_attached() {
    let w = Witness::new(30);
    let other = Witness::new(31);
    let (alice, icp) = witnessed(1, &w);
    let body = icp.as_bytes();
    let said = icp.said().to_qb64();
    let result = process(&[
        alice.frame(&icp),
        // A couple by a non-witness verifies but binds to no position: the event stays held.
        receipt(&alice.prefix(), 0, &said, &[couple_group(&other, body)]),
        // A witness signature that does not verify against the witness at its index.
        receipt(&alice.prefix(), 0, &said, &[wig_group(&[other.wig(body, 0)])]),
        // A couple whose signature is not the named witness's.
        receipt(&alice.prefix(), 0, &said, &[format!(
            "{}{}{}",
            count(cesr::core::counter::CounterCodeV1::NonTransReceiptCouples, 1),
            w.prefix.to_qb64(),
            other.cigar(body)
        )]),
        receipt(&alice.prefix(), 0, &said, &[wig_group(&[w.wig(body, 0)])]),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("pending", "seen", true),
            r("pending", "seen", false),
            r("rejected", "rejected", false),
            r("rejected", "rejected", false),
            r("seen", "seen", false)
        ]
    );
}

#[test]
fn receipts_for_a_held_rotation_or_interaction_use_the_governing_witness_set() {
    let w1 = Witness::new(30);
    let w2 = Witness::new(31);
    let (mut alice, icp) = witnessed(1, &w1);
    let icp_wire = frame(&icp, &alice.sigs(&icp), &[w1.wig(icp.as_bytes(), 0)]);
    alice.history.push(alice.custodian.params());
    let commitment = alice.custodian.rotate(spec(1, 1)).unwrap();
    let rot = keri_codec::RotationBuilder::new()
        .prefix(alice.id.clone())
        .prior_event_said(alice.last.clone())
        .keys(commitment.verkeys.clone())
        .prior_witnesses(vec![w1.prefix.clone()])
        .sn(1)
        .next_keys(commitment.next_digests.clone())
        .witness_removals(vec![w1.prefix.clone()])
        .witness_additions(vec![w2.prefix.clone()])
        .witness_threshold(1)
        .build()
        .unwrap();
    alice.commitment = commitment;
    alice.sn = 1;
    alice.last = rot.said().clone();
    alice.witnesses = vec![w2.prefix.clone()];
    let rot_wire = alice.frame(&rot);
    let ixn = alice.ixn(vec![]);
    let result = process(&[
        icp_wire,
        rot_wire,
        receipt(&alice.prefix(), 1, &rot.said().to_qb64(), &[couple_group(&w2, rot.as_bytes())]),
        alice.frame(&ixn),
        receipt(&alice.prefix(), 2, &ixn.said().to_qb64(), &[couple_group(&w2, ixn.as_bytes())]),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("pending", "seen", true),
            r("seen", "seen", false),
            r("pending", "seen", true),
            r("seen", "seen", false)
        ]
    );
}

#[test]
fn a_transferable_receipt_is_judged_against_the_receiptors_establishment_event() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let (bob, bicp) = Controller::incept(2, Options::default());
    let said = icp.said().to_qb64();
    let endorse = |sn, said_of: &str| {
        receipt(&alice.prefix(), 0, &said, &[endorsement_group(&bob, sn, said_of, icp.as_bytes())])
    };
    let bob_said = bicp.said().to_qb64();
    let result = process(&[
        alice.frame(&icp),
        endorse(0, &bob_said),
        bob.frame(&bicp),
        endorse(0, &said),
    ]);
    assert_eq!(
        readings(&result),
        [
            r("seen", "seen", true),
            r("pending", "seen", false),
            r("seen", "seen", true),
            r("pending", "pending", false)
        ]
    );
    // An endorsement whose signatures are not the receiptor's.
    let (mallory, _) = Controller::incept(9, Options::default());
    let forged = receipt(&alice.prefix(), 0, &said, &[format!(
        "{}{}{}{bob_said}{}",
        count(cesr::core::counter::CounterCodeV1::TransIdxSigGroups, 1),
        bob.prefix(),
        seqner(0),
        sig_group(&mallory.sigs(&icp))
    )]);
    let result = process(&[alice.frame(&icp), bob.frame(&bicp), forged]);
    assert_eq!(readings(&result)[2], r("rejected", "rejected", false));
    // A transferable receipt of a held event stays held.
    let w = Witness::new(30);
    let (carol, cicp) = witnessed(3, &w);
    let held = receipt(&carol.prefix(), 0, &cicp.said().to_qb64(), &[endorsement_group(&bob, 0, &bob_said, cicp.as_bytes())]);
    let result = process(&[carol.frame(&cicp), bob.frame(&bicp), held]);
    assert_eq!(readings(&result)[2], r("pending", "pending", false));
}

#[test]
fn the_result_holds_one_disposition_per_message_and_a_state_per_identifier() {
    let (alice, icp) = Controller::incept(1, Options::default());
    let (bob, bicp) = Controller::incept(2, Options::default());
    let result = process(&[alice.frame(&icp), bob.frame(&bicp)]);
    assert_eq!(result["dispositions"].as_array().unwrap().len(), 2);
    assert_eq!(result["key_states"].as_object().unwrap().len(), 2);
    assert!(process(&[])["dispositions"].as_array().unwrap().is_empty());
}
