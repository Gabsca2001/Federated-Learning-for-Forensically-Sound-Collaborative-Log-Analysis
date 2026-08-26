# M7 Investigation Report

## Executive Summary

This report presents a deterministic investigative view of model outputs whose complete M7 provenance chain has been verified.

- Cases reviewed: 6
- Candidate ATT&CK tactic hypotheses: 2
- Unresolved multi-tactic cases: 4
- ATT&CK not-applicable cases: 0
- Referenced source events: 69
- Referenced source records: 81

**Evidentiary qualification:** this report preserves verifiable references to controlled-ingestion source records and source files that define the primary-evidence boundary. Predictions, confidence values, Integrated Gradients, prototype geometry and ATT&CK mappings are model-derived measurements or interpretations and must not be represented as independently observed attack facts.

Reference labels and dataset ATT&CK labels are excluded from this report and are not used to construct its conclusions.

## Case Overview

| Case | Prediction | Confidence | Nearest prototype | ATT&CK status | Candidate tactic |
| --- | --- | ---: | --- | --- | --- |
| `m7-investigation-case-d4d7205d4da7c2b374415c85` | Multi Tactic | 73.91% | Reconnaissance | unresolved-multi-tactic | none |
| `m7-investigation-case-2c8dd514e715d3ef5079609e` | Multi Tactic | 94.81% | Multi Tactic | unresolved-multi-tactic | none |
| `m7-investigation-case-89577e54ca2de443daff989c` | Reconnaissance | 68.04% | Reconnaissance | candidate-tactic | TA0043 — Reconnaissance |
| `m7-investigation-case-a0c0c0e4273343047ab7758f` | Multi Tactic | 52.79% | Reconnaissance | unresolved-multi-tactic | none |
| `m7-investigation-case-e53d4ce5cfe52727c3046a5a` | Multi Tactic | 95.72% | Multi Tactic | unresolved-multi-tactic | none |
| `m7-investigation-case-498ee95ed92e641b997528a6` | Reconnaissance | 76.52% | Reconnaissance | candidate-tactic | TA0043 — Reconnaissance |

## Detailed Case Analysis

### Case m7-investigation-case-d4d7205d4da7c2b374415c85

#### Analyst Summary

The federated model classified the analyzed network window as **Multi Tactic**, with a confidence score of **73.91%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is **Reconnaissance**, while the predicted class is **Multi Tactic**. This discrepancy is preserved as explanatory context and is not used to alter the model prediction or the ATT&CK mapping policy. Under the frozen ATT&CK mapping policy, the case remains **unresolved-multi-tactic**. Explanation and prototype information are deliberately prevented from forcing a single tactic, so analyst review is required before a narrower tactic-level hypothesis can be made.

#### Identity

- Prediction: `m7-prediction-2f2c6e159d58da4f5a39a012`
- Explanation: `m7-explanation-6365313a26e3e71e4b275047`
- ATT&CK mapping: `m7-attack-mapping-06dde4a59835cc8368339dea`
- Window: `window-central-004edaae97e1e40f77e2`
- Capture: `2024-03-22`
- Split: `test`

#### Model Measurement

- Predicted class: `multi_tactic`
- Confidence score: 73.91%
- Raw confidence value: 0.73914539814
- Probability margin: 0.484652131796
- Inference input SHA-256: `fd4f35bfa6fac72c241fdc89cd12e120c5d04ddedbbf386f7108ea64ad8dba28`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 1.0728836e-05
- Top absolute attributions:
  1. `unique_destination_port_count` — 2.002505779266 (supports-target)
  2. `state_rej_fraction` — -0.890394926071 (opposes-target)
  3. `state_s0_fraction` — 0.870555520058 (supports-target)
  4. `state_sf_fraction` — 0.638679921627 (supports-target)
  5. `service_other_fraction` — 0.457847118378 (supports-target)

#### Prototype Context

- Nearest prototype: `reconnaissance` (2.772906278911)
- Second nearest prototype: `multi_tactic` (5.525661030686)
- Predicted-class prototype rank: 2
- Prediction matches nearest prototype: false

#### ATT&CK Interpretation

- Status: `unresolved-multi-tactic`
- Rule: `m7-attack-v1-multi-tactic`
- ATT&CK version: `19.2`
- Candidate tactics: none
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 7
- Source record references: 10
- M2 window lineage SHA-256: `95cf2fdae204543129eba896848531c320362f1351b59f9d6be80271ead1a5ce`
- M2 window row SHA-256: `e68331262a0482f3c4c9c11d8b7c7b503c984ca97e1a6c3098538d9932d3212a`
- M3 evaluation row SHA-256: `14e3d675aae23a2d8a541e54f319a8d01f204b9ee40f7456cf9e9550f519e7a9`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

### Case m7-investigation-case-2c8dd514e715d3ef5079609e

#### Analyst Summary

The federated model classified the analyzed network window as **Multi Tactic**, with a confidence score of **94.81%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is also **Multi Tactic**, providing geometric consistency with the model prediction. This agreement does not by itself establish class membership as a forensic fact. Under the frozen ATT&CK mapping policy, the case remains **unresolved-multi-tactic**. Explanation and prototype information are deliberately prevented from forcing a single tactic, so analyst review is required before a narrower tactic-level hypothesis can be made.

#### Identity

- Prediction: `m7-prediction-556b8dc4906ee4408e8a04c9`
- Explanation: `m7-explanation-65ce3c3b58a38aa313c89780`
- ATT&CK mapping: `m7-attack-mapping-734a396c78b2aa7ea6976d0c`
- Window: `window-central-0041895aef5212f39780`
- Capture: `2024-03-22`
- Split: `test`

#### Model Measurement

- Predicted class: `multi_tactic`
- Confidence score: 94.81%
- Raw confidence value: 0.948093831539
- Probability margin: 0.901493012905
- Inference input SHA-256: `6eb6557a79853771ef2151a6358662d2ca6586fc4d06579271b9b67f3ed69483`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 0.000714540482
- Top absolute attributions:
  1. `state_s0_fraction` — 1.851746082306 (supports-target)
  2. `state_sf_fraction` — 0.848492324352 (supports-target)
  3. `service_other_fraction` — 0.775874912739 (supports-target)
  4. `duration_mean` — 0.026357052848 (supports-target)
  5. `unique_destination_count` — 0.018668493256 (supports-target)

#### Prototype Context

- Nearest prototype: `multi_tactic` (3.513543299214)
- Second nearest prototype: `reconnaissance` (4.467199449287)
- Predicted-class prototype rank: 1
- Prediction matches nearest prototype: true

#### ATT&CK Interpretation

- Status: `unresolved-multi-tactic`
- Rule: `m7-attack-v1-multi-tactic`
- ATT&CK version: `19.2`
- Candidate tactics: none
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 1
- Source record references: 4
- M2 window lineage SHA-256: `5b4e7955c6b272a5be6dc2dbe7d7a6ea7e09e4642c6a17216293aec7d07ee95f`
- M2 window row SHA-256: `e36825ced1998155239a41b1ecfb424f64964971f0a98c580c96ee2031538e81`
- M3 evaluation row SHA-256: `73fbae091dc62cea08d1cebaa9324de38bb9894e98a5135b107e6e2d7ff9db04`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

### Case m7-investigation-case-89577e54ca2de443daff989c

#### Analyst Summary

The federated model classified the analyzed network window as **Reconnaissance**, with a confidence score of **68.04%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is also **Reconnaissance**, providing geometric consistency with the model prediction. This agreement does not by itself establish class membership as a forensic fact. Under the frozen MITRE ATT&CK Enterprise v19.2 mapping policy, the prediction supports the investigative tactic hypothesis **TA0043 — Reconnaissance**. No technique-level claim is made automatically.

#### Identity

- Prediction: `m7-prediction-8b0c5310d517726cc341bb2b`
- Explanation: `m7-explanation-80e1b24bf48642d8d1a30a1d`
- ATT&CK mapping: `m7-attack-mapping-ed08f25815821f4a0ebebe6c`
- Window: `window-central-003ee14815ffeb5989ed`
- Capture: `2024-03-23`
- Split: `test`

#### Model Measurement

- Predicted class: `reconnaissance`
- Confidence score: 68.04%
- Raw confidence value: 0.680438876152
- Probability margin: 0.414920151234
- Inference input SHA-256: `45f6fd179c4d71f9cfbd6ea35e675ff1902280f2ca7b40a91ebc6e914ea8b1c8`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 0.000107347965
- Top absolute attributions:
  1. `state_rej_fraction` — 1.696084499359 (supports-target)
  2. `service_other_fraction` — 0.625189244747 (supports-target)
  3. `unique_destination_count` — 0.375805824995 (supports-target)
  4. `state_s0_fraction` — 0.351842552423 (supports-target)
  5. `state_rsto_fraction` — -0.311499357224 (opposes-target)

#### Prototype Context

- Nearest prototype: `reconnaissance` (2.072470949733)
- Second nearest prototype: `multi_tactic` (5.970078382346)
- Predicted-class prototype rank: 1
- Prediction matches nearest prototype: true

#### ATT&CK Interpretation

- Status: `candidate-tactic`
- Rule: `m7-attack-v1-reconnaissance`
- ATT&CK version: `19.2`
- Candidate tactics:
  - `TA0043` Reconnaissance
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 8
- Source record references: 11
- M2 window lineage SHA-256: `ff0eebfb916b4d124911fd3f9446b9c2d119618ea85a93fcc8477ac02f46c02b`
- M2 window row SHA-256: `2569d22654a9777d447d10665a103d6f0eb65c4214d6ddd893d05d4c69a9cd8c`
- M3 evaluation row SHA-256: `82bb95c91f0bab8f6b662cc25a1272d014393bb8f2e83632950a1b66d8c5d9e4`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

### Case m7-investigation-case-a0c0c0e4273343047ab7758f

#### Analyst Summary

The federated model classified the analyzed network window as **Multi Tactic**, with a confidence score of **52.79%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is **Reconnaissance**, while the predicted class is **Multi Tactic**. This discrepancy is preserved as explanatory context and is not used to alter the model prediction or the ATT&CK mapping policy. Under the frozen ATT&CK mapping policy, the case remains **unresolved-multi-tactic**. Explanation and prototype information are deliberately prevented from forcing a single tactic, so analyst review is required before a narrower tactic-level hypothesis can be made.

#### Identity

- Prediction: `m7-prediction-90155793727152ee78beb4a0`
- Explanation: `m7-explanation-6f739386f43b5e09b3fb33f4`
- ATT&CK mapping: `m7-attack-mapping-fc6c50ed0b636af78de9f0e3`
- Window: `window-central-002ec93aa855b830ad1a`
- Capture: `2024-03-23`
- Split: `test`

#### Model Measurement

- Predicted class: `multi_tactic`
- Confidence score: 52.79%
- Raw confidence value: 0.527893185616
- Probability margin: 0.065730184317
- Inference input SHA-256: `9808f3ace5ccddf786849a3965e67b5104e824604d371395d55cd056c7c8e645`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 0.000361204147
- Top absolute attributions:
  1. `unique_destination_port_count` — 1.784355759621 (supports-target)
  2. `service_other_fraction` — 0.354371368885 (supports-target)
  3. `state_rej_fraction` — -0.335545688868 (opposes-target)
  4. `unique_destination_count` — 0.333941668272 (supports-target)
  5. `state_sf_fraction` — 0.310965746641 (supports-target)

#### Prototype Context

- Nearest prototype: `reconnaissance` (2.891474086132)
- Second nearest prototype: `multi_tactic` (6.782153113185)
- Predicted-class prototype rank: 2
- Prediction matches nearest prototype: false

#### ATT&CK Interpretation

- Status: `unresolved-multi-tactic`
- Rule: `m7-attack-v1-multi-tactic`
- ATT&CK version: `19.2`
- Candidate tactics: none
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 45
- Source record references: 45
- M2 window lineage SHA-256: `afd0282c912009e4963d66f23165894eb694dec049658e9989964fb4270c4b48`
- M2 window row SHA-256: `0ea3ae177f47846260dcd0c9dfae10257692d424b36c2c8b52e3d548e96072ef`
- M3 evaluation row SHA-256: `5279862604e79f0c4cc481696a49293849d21b4320c1a718c566695b501dbac9`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

### Case m7-investigation-case-e53d4ce5cfe52727c3046a5a

#### Analyst Summary

The federated model classified the analyzed network window as **Multi Tactic**, with a confidence score of **95.72%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is also **Multi Tactic**, providing geometric consistency with the model prediction. This agreement does not by itself establish class membership as a forensic fact. Under the frozen ATT&CK mapping policy, the case remains **unresolved-multi-tactic**. Explanation and prototype information are deliberately prevented from forcing a single tactic, so analyst review is required before a narrower tactic-level hypothesis can be made.

#### Identity

- Prediction: `m7-prediction-9662acda5c7775e6498c575f`
- Explanation: `m7-explanation-eb03c1f597bf6acf78c9d77d`
- ATT&CK mapping: `m7-attack-mapping-63cb0680fd77d02ab41c2163`
- Window: `window-central-000e916cc5653eba1d3a`
- Capture: `2024-03-27`
- Split: `test`

#### Model Measurement

- Predicted class: `multi_tactic`
- Confidence score: 95.72%
- Raw confidence value: 0.957238912582
- Probability margin: 0.9326633811
- Inference input SHA-256: `d16fc037971c5610236bd2cac1b4a5978c0a6bd3d671d15e4586399a2be7f4f9`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 0.000822782516
- Top absolute attributions:
  1. `unique_destination_port_count` — 2.148555755615 (supports-target)
  2. `state_s0_fraction` — 1.038453578949 (supports-target)
  3. `service_http_fraction` — -0.777718484402 (opposes-target)
  4. `state_sf_fraction` — 0.322370409966 (supports-target)
  5. `service_other_fraction` — 0.30451002717 (supports-target)

#### Prototype Context

- Nearest prototype: `multi_tactic` (4.461084824584)
- Second nearest prototype: `reconnaissance` (7.082468301889)
- Predicted-class prototype rank: 1
- Prediction matches nearest prototype: true

#### ATT&CK Interpretation

- Status: `unresolved-multi-tactic`
- Rule: `m7-attack-v1-multi-tactic`
- ATT&CK version: `19.2`
- Candidate tactics: none
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 2
- Source record references: 5
- M2 window lineage SHA-256: `91299d2e5d434fa7839d55265dcfa5dd0af806b3d8c376e66dac9ccb4291786a`
- M2 window row SHA-256: `d181b7eebfeda27edb44a33f5e9cc502a86eba2e1a7addc94445c5b04576c572`
- M3 evaluation row SHA-256: `47f0f57154fa05c52c983635e03df60b4cd7a7fc70755bc257d022bf9f1ca7d6`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

### Case m7-investigation-case-498ee95ed92e641b997528a6

#### Analyst Summary

The federated model classified the analyzed network window as **Reconnaissance**, with a confidence score of **76.52%**. This value expresses the model's confidence in its own classification and does not independently establish that malicious activity occurred. Integrated Gradients identifies the input features most associated with the predicted-class logit, while prototype analysis provides similarity context within the learned representation space. Both are explanatory model outputs rather than primary evidence. The nearest training-derived prototype is also **Reconnaissance**, providing geometric consistency with the model prediction. This agreement does not by itself establish class membership as a forensic fact. Under the frozen MITRE ATT&CK Enterprise v19.2 mapping policy, the prediction supports the investigative tactic hypothesis **TA0043 — Reconnaissance**. No technique-level claim is made automatically.

#### Identity

- Prediction: `m7-prediction-fb795dc5ada91e4b831c12e7`
- Explanation: `m7-explanation-566cce4bca71c5c358aea35b`
- ATT&CK mapping: `m7-attack-mapping-2353277087453f3e98d144f0`
- Window: `window-central-001798b1c92400003e9a`
- Capture: `2024-03-22`
- Split: `test`

#### Model Measurement

- Predicted class: `reconnaissance`
- Confidence score: 76.52%
- Raw confidence value: 0.765174567699
- Probability margin: 0.548968613148
- Inference input SHA-256: `a3542a308c03ff65eb2d417776680d954691168ec8c3d9be67b819555cedf35e`

#### Why the Model Reacted — Integrated Gradients

- Absolute completeness error: 0.000303447247
- Top absolute attributions:
  1. `state_rej_fraction` — 2.185792922974 (supports-target)
  2. `state_s0_fraction` — 0.638074398041 (supports-target)
  3. `service_other_fraction` — 0.587728917599 (supports-target)
  4. `state_sf_fraction` — 0.281493514776 (supports-target)
  5. `unique_destination_count` — 0.154380097985 (supports-target)

#### Prototype Context

- Nearest prototype: `reconnaissance` (0.659648805253)
- Second nearest prototype: `multi_tactic` (6.489944439191)
- Predicted-class prototype rank: 1
- Prediction matches nearest prototype: true

#### ATT&CK Interpretation

- Status: `candidate-tactic`
- Rule: `m7-attack-v1-reconnaissance`
- ATT&CK version: `19.2`
- Candidate tactics:
  - `TA0043` Reconnaissance
- Candidate techniques: none

#### Primary Evidence Summary

- Lineage status: complete
- Source events referenced: 6
- Source record references: 6
- M2 window lineage SHA-256: `37fe5f78340c08814ca696f3785dcdba8603dfa78522a1fad61a6387ae5acb41`
- M2 window row SHA-256: `a74e1cbcaf945f8b1d574e9204557295826e6caf73d5df012338489d233c3d64`
- M3 evaluation row SHA-256: `bdbf82c99e5a3affbbe6f0f8a58ecc9e62ca7100e1099658c27622f9c811b254`

Complete event- and source-record-level references for this case are preserved in the Technical Evidence Appendix.

#### Evidentiary Assessment

The source-event and source-record references associated with this case define a traceable primary-evidence boundary. The predicted class, confidence score and probability margin are model-derived measurements. Integrated Gradients, prototype geometry and MITRE ATT&CK mappings are derived interpretations. These outputs may support investigative review but do not independently establish that the hypothesized attack activity occurred.

## Method and Evidence Boundary

Cases in this report originate from a verified Prediction Bundle. Each selected evaluation window is resolved through the verified M2/M3 lineage to controlled-ingestion source records and source files.

The report does not copy the original source-record bytes. Instead, it preserves paths, row references and SHA-256 commitments that allow those records and their source files to be verified against the controlled dataset workspace.

Integrated Gradients describes local model sensitivity along the configured baseline path and must not be interpreted as causal attribution. Prototype distance describes geometry in the learned embedding space and is not proof of class membership.

MITRE ATT&CK mappings are versioned investigative hypotheses produced under the frozen Enterprise v19.2 mapping policy. Explanation artifacts cannot override that policy, and technique-level claims are disabled in this report version.

Reference labels, dataset binary labels and dataset ATT&CK labels are excluded from final reporting and are not used to formulate investigative conclusions.

## Technical Evidence Appendix

This appendix preserves the complete event- and source-record-level references used by the cases above. It is intended for verification and forensic review rather than rapid analyst triage.

### Evidence for Case m7-investigation-case-d4d7205d4da7c2b374415c85

- Prediction: `m7-prediction-2f2c6e159d58da4f5a39a012`
- Window: `window-central-004edaae97e1e40f77e2`
- M2 window lineage SHA-256: `95cf2fdae204543129eba896848531c320362f1351b59f9d6be80271ead1a5ce`
- M2 window row SHA-256: `e68331262a0482f3c4c9c11d8b7c7b503c984ca97e1a6c3098538d9932d3212a`
- M3 evaluation row SHA-256: `14e3d675aae23a2d8a541e54f319a8d01f204b9ee40f7456cf9e9550f519e7a9`
- Source events: 7

#### Event `event-central-d63f54a11ac875489ebf`

- Lineage record SHA-256: `30c1f5491e87b048300d9406962add0fd475d91c44b832f4010660816d2da6b9`
- Source identity SHA-256: `d63f54a11ac875489ebf524dc12a19378e33503ea000ca408758ea2388537e86`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 29368
    - Record SHA-256: `50b3db39b6f49d0f8932fb3d18181a54db9088e1478eac98f5f75b7ba81a0a23`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-a60a9ae489b2134711bd`

- Lineage record SHA-256: `92d26084761019e8ce186cdd57e82df39f7a13b779c12333038b258a3473e4bc`
- Source identity SHA-256: `a60a9ae489b2134711bdaa092d740c5d6d63c63138ba4777a9b6156a45c35fae`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 165409
    - Record SHA-256: `b974b9d7fc394ddffe9b5c2b1d05915f6dedc6c550c98511d95069473a589575`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-013a71ec2b6a2bce81cf`

- Lineage record SHA-256: `d8da86b474652331b89e47e7f37c237a799010aa51774d760e4d8e2296588fb4`
- Source identity SHA-256: `013a71ec2b6a2bce81cfe7bb7bd1e66eca42ec6d232b8724e8ec96a3d3996adc`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 220935
    - Record SHA-256: `85d38640a0b35576681812e208b396cf0f2ae866ce45d8b8863e9d1184fadf5c`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-c56e993e8a10163291aa`

- Lineage record SHA-256: `ac27a61a5c0b93b0fb7674f9b46edda2a7da43added2e2a12631c1b958a28211`
- Source identity SHA-256: `c56e993e8a10163291aaa4b0e28ebf0b4b2356e48372d1cfbdd5ae0ea281c8ef`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 266897
    - Record SHA-256: `475e21ee90d587cccb5f00eeef44029041e9850ba8455674537143fab9fd1ee1`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-bddbd5ceea43b6eb0535`

- Lineage record SHA-256: `2fc13fa6a368e4e803882703be418dc75e35c9c96a0adcd7e61eacc3bac81916`
- Source identity SHA-256: `bddbd5ceea43b6eb0535b5733a84d61237a6791464c98c4dbbd48ed89eab63cc`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 64300
    - Record SHA-256: `1e73fd0725ccde02cc435f0021165ddb692db58e5a8503157ec584097006e686`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-1b95778602d6c6989b9d`

- Lineage record SHA-256: `bb4df936b42e869175729854d97237089c3341c6a264c75bc4903dfb123cdea3`
- Source identity SHA-256: `1b95778602d6c6989b9dbe12905f80de3a70f39874c2a8eeb86d2cdec3ccd052`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 193053
    - Record SHA-256: `be25c69d03733c96caa9dd09cd24357ef2b1802670fcb71d767daa09616d4335`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-ed391b04b52dc34f10a4`

- Lineage record SHA-256: `9eb15306b3799b54685a2a5450c3d5ffb32779414dcdfd699c61e0c1cea8e78b`
- Source identity SHA-256: `ed391b04b52dc34f10a461d59452dd6a79d2967ed734b246daed2ec4fb6a429f`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99059
    - Record SHA-256: `0f03cc558779a7bccde5cd90e984e6261997a1a38d7eb16e4186113f9124706b`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99060
    - Record SHA-256: `7f5be54e71576a27c4feba657a00b5db87df0c70531b73c36302b8737bc8cf19`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99061
    - Record SHA-256: `3b082e5cda670d76868e23b1649e2389804b3c131ca4279fffe8376fa8f9f08b`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99062
    - Record SHA-256: `72f135c9e9519e965449ee8447601722108950e4bc39ebae780b68b4aae5c862`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

### Evidence for Case m7-investigation-case-2c8dd514e715d3ef5079609e

- Prediction: `m7-prediction-556b8dc4906ee4408e8a04c9`
- Window: `window-central-0041895aef5212f39780`
- M2 window lineage SHA-256: `5b4e7955c6b272a5be6dc2dbe7d7a6ea7e09e4642c6a17216293aec7d07ee95f`
- M2 window row SHA-256: `e36825ced1998155239a41b1ecfb424f64964971f0a98c580c96ee2031538e81`
- M3 evaluation row SHA-256: `73fbae091dc62cea08d1cebaa9324de38bb9894e98a5135b107e6e2d7ff9db04`
- Source events: 1

#### Event `event-central-233e83ab16ff7dab5e30`

- Lineage record SHA-256: `11468a067156a0aad356356942ed26ae0a7f17bfe9340cb77fed536ae0b678a7`
- Source identity SHA-256: `233e83ab16ff7dab5e30eb1e543981c6a4c8ace205c2c681aba1e11454e7cc71`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 359954
    - Record SHA-256: `d6dcdc5a5dfe13fcc309e350b5dd83a16fc221437492d7deab22e609921f7fac`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 359955
    - Record SHA-256: `3b8a4f8b2ea67b1451e896e2eec786f003929b92d9e3af63a483ef6d2e276967`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 359956
    - Record SHA-256: `a6a5d7243326d792d07c13915e36f60f67e5b1cd58f2a59905c09c8cb0245e04`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 359957
    - Record SHA-256: `53076b421e04c4ea37a1cbc18790e8db33e302238d2159255f0c53dcdd006598`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

### Evidence for Case m7-investigation-case-89577e54ca2de443daff989c

- Prediction: `m7-prediction-8b0c5310d517726cc341bb2b`
- Window: `window-central-003ee14815ffeb5989ed`
- M2 window lineage SHA-256: `ff0eebfb916b4d124911fd3f9446b9c2d119618ea85a93fcc8477ac02f46c02b`
- M2 window row SHA-256: `2569d22654a9777d447d10665a103d6f0eb65c4214d6ddd893d05d4c69a9cd8c`
- M3 evaluation row SHA-256: `82bb95c91f0bab8f6b662cc25a1272d014393bb8f2e83632950a1b66d8c5d9e4`
- Source events: 8

#### Event `event-central-434b27d910db808e88b4`

- Lineage record SHA-256: `1c84632b956c2b6421ed745c8dc4b897d2181a873cc375721d996841976a0fef`
- Source identity SHA-256: `434b27d910db808e88b4ac287f66d1a27c9183fc369a1d534a9e3bef23eb7046`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 63253
    - Record SHA-256: `46e060f8d58c6dcceddc09bc3f29e77f504db764acbf5db0d1ad9d0f5f881f48`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 63254
    - Record SHA-256: `8d00aea6d62e4c5a17544676d778c275afed7ec034baf3523dc0749e14a6de53`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 63255
    - Record SHA-256: `29e6f0b250f185481b41f847c51c231a192b6bb24a51782f0c69ba7dd60984a6`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 63256
    - Record SHA-256: `7975d81f55f30722ebdcd72d2206c843d1df3cd4d31f05c9a18eee1c5eb3d7c9`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-4304f2a24b173de1ed1f`

- Lineage record SHA-256: `531f039cc8aee7ebbfa7f0ab84d43c425e6c1c7a962828458ab620e1dc1cdb45`
- Source identity SHA-256: `4304f2a24b173de1ed1f09cd0c34bf200df1e3007f6df4c6cd4d3d3c8417e54b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 313987
    - Record SHA-256: `765505430414f52954d3891c89d870ec1161bbeb407c2e7516ebcffc04c0a551`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-261dc15be4426c14f911`

- Lineage record SHA-256: `5fae22090b374f9cf2d2d19ae8fcfd3b3f429e85013dd59a54c59085b80ba017`
- Source identity SHA-256: `261dc15be4426c14f911198f52c15a16db5cfd87dfe20a2ce48f4b2480129859`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 248444
    - Record SHA-256: `1be8cd42640c712d7aca1d45468431eae23ed4f7e05d62a9f1bf501fade7ac7a`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-eafc0a3e5516cd368b04`

- Lineage record SHA-256: `90809de3514d5aab3fc59a922164e50a1f0f5331e2987e6641c833db77a18c92`
- Source identity SHA-256: `eafc0a3e5516cd368b04ec70be35847204f4e755d256c812ece33468c33b7e21`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 220967
    - Record SHA-256: `33f7cbb1ff4c5c403be0c2286403ec2f8a03e85b6f9d46996f675e857f696df2`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-31ba73b8617b3dfb712e`

- Lineage record SHA-256: `90510cc167d8226758936133273f2364389c27444225e69d86d9102f025602cb`
- Source identity SHA-256: `31ba73b8617b3dfb712e82192de8397997f89e956bd6fa189d83ed91994ee30f`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 174947
    - Record SHA-256: `357f425a21d00eb4f269f863707a936a1231331fa4a9af4b183442389ec17249`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-1c43180770ed3e33deb7`

- Lineage record SHA-256: `e97a381c021c57c68cdb1301799bfa8236f32966cb153cce21680531008d5e41`
- Source identity SHA-256: `1c43180770ed3e33deb7effa6f4732c380f1e01baa3c90a661a55e999621a35b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 323340
    - Record SHA-256: `f8cc3904d105c7ef9e8ab72bde2569a7b62735cc22b12ca2cc44dd871bd42970`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-d238510d3b920b49da7c`

- Lineage record SHA-256: `6e6c1992f69a588e662f0ee59cd6dfffff203c708cf071940851b3a06e350996`
- Source identity SHA-256: `d238510d3b920b49da7cabd0fc08cfd72cb588f253b32ee94b087066392ccf57`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 304495
    - Record SHA-256: `9b80542154d543ac7e6714cc389eb5ecfc0ec22ad1bc5a2b6b9badc1c8f4c4ff`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-02710ab6debf0f8ab2b4`

- Lineage record SHA-256: `aa324b056a63e77648d251c6674df50814244420dd509db29fd54c37a5f3719e`
- Source identity SHA-256: `02710ab6debf0f8ab2b446fab394d5a34ecfc054b865eb4fb92a58903d92a4aa`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 351108
    - Record SHA-256: `3fb3e3f8602a334c98914bb59f80fc7efbddd764b674e1aaa27b975837cf4a6f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

### Evidence for Case m7-investigation-case-a0c0c0e4273343047ab7758f

- Prediction: `m7-prediction-90155793727152ee78beb4a0`
- Window: `window-central-002ec93aa855b830ad1a`
- M2 window lineage SHA-256: `afd0282c912009e4963d66f23165894eb694dec049658e9989964fb4270c4b48`
- M2 window row SHA-256: `0ea3ae177f47846260dcd0c9dfae10257692d424b36c2c8b52e3d548e96072ef`
- M3 evaluation row SHA-256: `5279862604e79f0c4cc481696a49293849d21b4320c1a718c566695b501dbac9`
- Source events: 45

#### Event `event-central-cc372dc792a20125e493`

- Lineage record SHA-256: `c31152b84b6bdc61cf4527b316ef86a4802c4ae9c1aca4368d7a09f73e04b196`
- Source identity SHA-256: `cc372dc792a20125e4930795c284dc22104448ae096a1e5718a42732fd87c4e5`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 323263
    - Record SHA-256: `eee4da449e8039e04929f5f8eddcb78f2cc78978b9106172baacfed39d87d44f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-7038c6371af2ffa583d9`

- Lineage record SHA-256: `d49662af93fb7cf92b9d901131a1bb6d910ce8519dfa9014cd800f8c5fd0a4fb`
- Source identity SHA-256: `7038c6371af2ffa583d9d510905ebc2b997c00cd6223d74cb07c6ff42308887e`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 258170
    - Record SHA-256: `4d5c2e42d1ad7ebfe43b0f39172c4a7f42502ee1fd493b713caf5eff7a652206`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-4324be06c8000a24c591`

- Lineage record SHA-256: `8a5717cf0f8c2ca942d07bbb2234a0f02943b26ada298d1c247298706f8955be`
- Source identity SHA-256: `4324be06c8000a24c591e459a5cad2e5eaed69fac565a6008cc91a470559fe9e`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 29284
    - Record SHA-256: `544cdd3d2096d60e03ed027d701a46ed17aff2aa0809c44b9a375b5bea55bc9a`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-eb8453df2c85c0c2b15f`

- Lineage record SHA-256: `a4a548d169d9c0e4c5d2c6dc21453b9b51522952a35cf77af7fe10b110dd09f0`
- Source identity SHA-256: `eb8453df2c85c0c2b15fdbf33a49ee885228dbcd5debe629393118d3e8436b82`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 100214
    - Record SHA-256: `eb37fc64bea39150d0f3ec57e0f0ff436c9a627a563e758f5c8afa554f54c44d`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-f5c30cf4532698a56856`

- Lineage record SHA-256: `8bb2621b1fbff90a36b3b9def43cc7a4427dac114cf8c6604abf8408924ed09e`
- Source identity SHA-256: `f5c30cf4532698a568565f45601cbd60847e0479dd813544d80de5a9a1d5ec90`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 1250
    - Record SHA-256: `4be99c10208cecf7d205ac2c8d6e413cd2813c2f46430a0de16b496ad1709785`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-9af2a2d29950f1e1ce01`

- Lineage record SHA-256: `a5ce80bff48f46c9736dff499ab0fa1aae0f1df3dfd740ca85fc0fe520a78955`
- Source identity SHA-256: `9af2a2d29950f1e1ce01214f6a39495918568bcc2e421ab48d5767e57fd0481b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 1610
    - Record SHA-256: `30bedc2ab3d0d43901bffe54063e161c4a5de369bc5349eac68f3ad4c8075fb3`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-92ef295e00c284fbf53f`

- Lineage record SHA-256: `efbc575fe7bb228d072144dc7aa4c489dda6028ab6d5b3024465cdb2fe59729b`
- Source identity SHA-256: `92ef295e00c284fbf53f0b3c459466b23ab022753e27202c18ab610809ef406d`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 193112
    - Record SHA-256: `808bf9e50c439d2023b16942200a98cc73247585e8e94157a203e713f4810b72`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-d1302121c0943b591fb6`

- Lineage record SHA-256: `c1758ce3150292262276ab3bf51833bfd61371df73f54d1ae599b23c171f65dd`
- Source identity SHA-256: `d1302121c0943b591fb64ffdfe5352f4f5039b43d2dd94e6144c77624409dee1`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 165332
    - Record SHA-256: `53bbe9dc34354d97cd4d1c7dff0c0864dfa1d0831f1ea084e682e26f279d6374`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-364e94296480065125ca`

- Lineage record SHA-256: `69043192544b093a71f5dc9d0f07d297061758c7c4edbda6f2a6474981a7c303`
- Source identity SHA-256: `364e94296480065125cadc7fae37ab4ab0518825951c30a96373d9bd047fef6c`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 193760
    - Record SHA-256: `2a95e628a1dadfb04751c65fbb76fa715395a444a3bb880d26334e9ee8331071`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-ba67cbcb195661d27d62`

- Lineage record SHA-256: `d02f8c5f85acec0b7a46e944275b8bd869f64441ccdfcea4ebc2a4a5a5ca5fd6`
- Source identity SHA-256: `ba67cbcb195661d27d6209b80942ba27668220a45624cc6ea55bee571b190c15`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 350786
    - Record SHA-256: `0106bf01c656a6d84d61711aac3fd03fb5227b7441ff7013bb6bf942d92487ed`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-d2eab82ff921e45a4e31`

- Lineage record SHA-256: `fb7462bf73422d61fef414d95d42125bae170db4ee771955299d24c23ef2618c`
- Source identity SHA-256: `d2eab82ff921e45a4e310d07711619b616795ce6bad6c0438935d0634189319d`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 322342
    - Record SHA-256: `65d42eeed58747b6688c1da5428662b37b7590b04221cf758c4d5939d029ad13`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-bbaec65e12ba510b9b9a`

- Lineage record SHA-256: `0158796ea0cb3fdce5c9a69447b89137f2af2ff220952c65e383b9b9c4acaadd`
- Source identity SHA-256: `bbaec65e12ba510b9b9a722485fd8392bcf76867877413670d2bed9607223606`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 164712
    - Record SHA-256: `d17632b52e1a65f3afbebd591d78edc7a3d92ec6df9f3d92153a0dcfe86d1168`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-a542f16bddb0855e8dae`

- Lineage record SHA-256: `488571c0b3e4919368129b53108d5f89f0a17e9ba016fe1ff7473a94f82d273c`
- Source identity SHA-256: `a542f16bddb0855e8dae9963619a4adc962c3dd71723cd6ef34f60c3eeb2472d`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 174379
    - Record SHA-256: `6eefea5aafccb0c4c7038c1f8d09e5fa1ab0ca70d302a9d75d1c9460eae71ade`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-ca08c590254afa4be29f`

- Lineage record SHA-256: `9bb090862f87e2f7347e0504498c50b75707fcb631c74b8c18df4502a44c17e0`
- Source identity SHA-256: `ca08c590254afa4be29f74d160b85deeae0faf5c43d405616660ae8cb7104610`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 257052
    - Record SHA-256: `d7ce5e557cf4f964588101f227e07a538d6bb02824083298ba5d6b06f30fc82c`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-5dc699ef7f5f4990f46b`

- Lineage record SHA-256: `c4b21a30aca05cc65a4336361668bdc92e1e37b028f10f338f53816841d17259`
- Source identity SHA-256: `5dc699ef7f5f4990f46b95c74524b46f78935761eed42bbfbb9c742c2003929a`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 561
    - Record SHA-256: `dfdc7498d885eb50c4ab5e7ab104173c58bae79f7e89ffd1f926ae3608d0d59d`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-b386b05c7933c4c3089d`

- Lineage record SHA-256: `75fde00069e1692be84e6ecc04426294e56133285124c8e8cfdba744fbbd38e7`
- Source identity SHA-256: `b386b05c7933c4c3089dac93660087861ce890069985d540a26490fb43013813`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99249
    - Record SHA-256: `e4a81f716254f955edc3cf6cfc134d520ef8c1ae41ebc7f0779cb48cd33d152d`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-ea3f7394879746e8d365`

- Lineage record SHA-256: `094575818a6ec22d6aa02f52e844977a02caf5bf584483c9ef83eb0dbb92efd8`
- Source identity SHA-256: `ea3f7394879746e8d365685436b075a88a03b412949b27444f3e661beccf9071`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 275863
    - Record SHA-256: `7d103fbb446776fa0190f34d1b10f904507579484f2c888115efc0c597ee8911`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-00d7f8cce6d8edabf1a3`

- Lineage record SHA-256: `7ccaede863760f2afaaa41278f1f54b20ebebcafc73ee6f6b664c2240038904a`
- Source identity SHA-256: `00d7f8cce6d8edabf1a3ecf04f614a3aa6c8c35e475188796862300a2d4077f4`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 164713
    - Record SHA-256: `b203ee71202b0f3efe8234a8d8de0363335eaa6884999ae758626f14c701fc70`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-8b2a05bb3b56e7954a5d`

- Lineage record SHA-256: `1b160e6ae276cedd6812bc59d6322dbb00ad338a97cb79f7dbf03fb3ccfde5db`
- Source identity SHA-256: `8b2a05bb3b56e7954a5d3d5aecf94ae9c5a5a27c71a1e3bdd66635cc6ab7c50e`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 313019
    - Record SHA-256: `a1450d4c47b6db80f3b55bc0bea59b6d43ca777740d34c2126b9ac83c565cc96`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-b7ff3beb67db3439b947`

- Lineage record SHA-256: `ec01d4c712f904dfb648f87b83d713fa1a040c42b3c3030a68b3734f53e86671`
- Source identity SHA-256: `b7ff3beb67db3439b947ecec4ffa5ba06b69f5a9f0bb2f01d4e410f1c63fa091`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 73156
    - Record SHA-256: `8aa8d70978d0c2888e412c8f31627f3ecd12c218cb2e84231789cc36036d0a5f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-9d5ef5965436ce668b01`

- Lineage record SHA-256: `b12ee0b2f214b4a5528232dd8c192580c3c42b9846121aa0d7ffd5f88898af2a`
- Source identity SHA-256: `9d5ef5965436ce668b01e0fe0f0f8885ebcc0644be648abc57ca6b82a71ce5d2`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 28396
    - Record SHA-256: `8c19340ccb3f3dc6933c1b2f7d2c19c3f1198b540f927dbc95dbc59ab60b380b`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-1d2b22d1e60af407341d`

- Lineage record SHA-256: `95b6c0021817dc28e106efb58d44ddb7785624351619c2ad35a208704a711221`
- Source identity SHA-256: `1d2b22d1e60af407341ddd994ad173a4ad0f80d893edea94075ab24f5f4321d2`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 73157
    - Record SHA-256: `ae3e09c68e6322ef59ee8190c9b12f1886f61a5160605561d9f1819922fe190a`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-6f0ce11af8d730489e88`

- Lineage record SHA-256: `5da36d7cc3f874a30dff6f2310cec121266fbd2140e3564e2de352190b159eda`
- Source identity SHA-256: `6f0ce11af8d730489e88f5757fca8d59c766e255f13df27a96f53fb4b7d781ad`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 341121
    - Record SHA-256: `0654cfb76d61e792e0a7a52b9b00a8e840e31ed18317d8ed692a34cb840a9eae`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-6c520418b1422866979d`

- Lineage record SHA-256: `7f7ac30e3e5fbf8271b0e527c18f978487c1edd9b39ddbe48babaa43823fd274`
- Source identity SHA-256: `6c520418b1422866979d5e1d9de52657750d4151ff0a7e4831d735e3b046b1af`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 266524
    - Record SHA-256: `6b36d97e25bdad4d2cffae87e366aa845fa7f9a4e432de6909618659a9c0710b`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-1830098aab922abfffb4`

- Lineage record SHA-256: `7f186672fd837d16690e7b9613c3f7c41ceb45ee023e7eaf65a23be1a042f5df`
- Source identity SHA-256: `1830098aab922abfffb4622d039277b5c5a7994ccff66379f28edd06f3ed5a59`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 192584
    - Record SHA-256: `b7586461e2385f9d4a0b62578bf699fb0f57fd897d632de28de9aa39df29fabb`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-445bbbee0b86e03e79b0`

- Lineage record SHA-256: `fd1723552a7a9b7ff52582cc250898267efeab3ce52f18e6cb6ea12a49283c7d`
- Source identity SHA-256: `445bbbee0b86e03e79b093dc1fbcce760beda4939acb51341581edf5651b0267`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 164714
    - Record SHA-256: `87d051f3c0ed91ddeace79c56426dd92cbfafc039f34f8165d0706aa443da310`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-4d81755ceab79336fc17`

- Lineage record SHA-256: `8600765eb2eb7c3eb241392c0da3c2e45cf2bbdd0a731a15a195fc817e4e00e8`
- Source identity SHA-256: `4d81755ceab79336fc17849528ac61ff6fc35594c477d17b9bf7ac9232916014`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99248
    - Record SHA-256: `2c2f5c86fcda28ca9ced43f538d7e66942d84b883f2436cd080cf9cffc86a546`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-889e37f8d75f52110780`

- Lineage record SHA-256: `4cfa306b646eb683e211c6c81bb3c4ad5565c2e55a63770c05d8c0c52e0fd1ea`
- Source identity SHA-256: `889e37f8d75f5211078024fa5b11562bdad7029a2ffda498cc1e035d948a7b43`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 369935
    - Record SHA-256: `fe9aa4f0106f1b82b87d3da69987318e62a2de6bac9eae576aacccbcf1fb8ae3`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-d44eefcb61299864ee86`

- Lineage record SHA-256: `c558a806cb0c3d83150fde06498ebbf83440d4ade9ea18e293d6d56e1b15e547`
- Source identity SHA-256: `d44eefcb61299864ee86da57a91c7d5dffe9c0618cd2fb19eee20713e9b894e0`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 350787
    - Record SHA-256: `16c814fd72a91850ef1cf6929798dea41088fd6e265e3f48c5de8a07ad07bc87`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-a48d68d172ae6131823a`

- Lineage record SHA-256: `9fae27c76a787719e97acf00e478e00b43cb7b81f17f4709b9aefd9bb97d484c`
- Source identity SHA-256: `a48d68d172ae6131823a826f923f100717d2a3be5e196679b7c72699c4f6bda7`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 350788
    - Record SHA-256: `9dc106601680fbdc9ca6491551be47cfed944d66831382c53d9f9eae93186ba8`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-352375f951c848ce0626`

- Lineage record SHA-256: `0392216212a2c7633b39a0476930ef94e2444cadea8fa2d07cfffec97b5954e0`
- Source identity SHA-256: `352375f951c848ce0626ce8273b7d0ae7820549955900712a31bfa272ae6400f`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 331870
    - Record SHA-256: `20d6dfe28c9eea7645d00f21cf354d9ff0902f0a56cf08a4998efc2a188788b4`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-7c9c1b02d19587c29ae6`

- Lineage record SHA-256: `b61837ace173e01a8b7fcaac1e0bb749ca3f68f4ecea7d43891d3a70933770e0`
- Source identity SHA-256: `7c9c1b02d19587c29ae66a44d7d4ea6c82e33ab7805122fb047c12f35feed8fb`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 350789
    - Record SHA-256: `e080374a2d59f0edf71822e2e4b6830bfa8282eba2765487cbabbb24f87ae870`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-5634d8e8925e429f6092`

- Lineage record SHA-256: `1ba96bd7ba5425a03125046562a8483238d3549b49d397a3993e6940e3188d03`
- Source identity SHA-256: `5634d8e8925e429f6092cb870fdc56c4b452e33e23dd7794bbff0e8da0de2b62`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 174380
    - Record SHA-256: `a5fb68f11f1103d9dbd8d09456764941b4ce4365a41e627132d8144f61d4de74`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-9c21c22de29b9f1f0145`

- Lineage record SHA-256: `4204de1c88837cf8deedd7abeb4d7beb897291cfa3bc69f1ee7f54cf5b4bf372`
- Source identity SHA-256: `9c21c22de29b9f1f0145b3e7c31e740b6b1ffabaa691f8a9b3300ac6069fbd01`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 164715
    - Record SHA-256: `9a8b6274db0c1fe92fc51599d0df67156c3ccee24a113d75dd22c5e1ff9bca22`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-196b2dcf9f5b9ea5e9df`

- Lineage record SHA-256: `e218f8818504dcd49777bccf87ff42bbbba72b2105af42b5b6ec865c6edd336c`
- Source identity SHA-256: `196b2dcf9f5b9ea5e9dfaf1ca836baf8a215ab0d4cc94fbc847b99918401126b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 192585
    - Record SHA-256: `eb5e2003cfdc0589d741ab6fb42fc582a0b9617123f70eaa4eeb1b2ac4e9e4a9`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-798c71bb1d5b51b1e62f`

- Lineage record SHA-256: `276087ecf5334c48f15f810493bb0bfab1ff2f2dfbd029160719244b9b2a9ec0`
- Source identity SHA-256: `798c71bb1d5b51b1e62fdda2ecbebe4b065e546a0059ad99c6cb46624e7f2d3e`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99250
    - Record SHA-256: `48357b9944b7e32505ccaa378bf9579885ae7c82679e8b526b992d9326979ea4`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-8e3bcdc404987fe000c9`

- Lineage record SHA-256: `46f484e4b954d012f78f9daaeab9d998a6b7a93e662c75f71b9074fe81e88dff`
- Source identity SHA-256: `8e3bcdc404987fe000c9ce1bde028b82494c4383971abe6d50e6283fcd970f1c`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 63566
    - Record SHA-256: `3db966e60fba925a091f182e3162672c8656fbc34955675982e73f042984cf4f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-787b856deedc5cea890f`

- Lineage record SHA-256: `38b5f857469c0484dad2cb02c1bbbb8216fe7fcf3b8c6a80cd6f6007ca91037c`
- Source identity SHA-256: `787b856deedc5cea890f6e7c4fd095eb61aa26f3017b3714f00a767c90899fc4`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 99251
    - Record SHA-256: `3ebb7b0ee4ac62baed4b265bec815632fb5b1979f5157b2239879c43287ec67d`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-b9a88b9c10b2db03d83b`

- Lineage record SHA-256: `d866281bc2f883f27554e672f8dd5fde83920759a8ce38393575a0a416a1a794`
- Source identity SHA-256: `b9a88b9c10b2db03d83bbd115c651045655499e539916e6a774f18e820f145f6`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 219988
    - Record SHA-256: `dbd4ed8998c81c1979f4376fa52543001dcd8e4a1d89d72450aa28b6b9f23b55`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-a5b70984d81f2a708857`

- Lineage record SHA-256: `ef831fe5c8cc46b20b2c5b8c7d8afadbb5ed545f6dbeda7c636339db3d1b0189`
- Source identity SHA-256: `a5b70984d81f2a7088572dd1a6ed98369bb6bde4df64572e0e4de994a831d25b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 562
    - Record SHA-256: `acf5ec42aee87e540744f918e469ce92c65762de776399981f0eb5b4f0326497`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-240517169145eab04a45`

- Lineage record SHA-256: `4fb2edcfebef8ba7f1eb867fa1cee2ec52336a00abe99d0806ff66be8404404b`
- Source identity SHA-256: `240517169145eab04a4533e1de6649f1ee6ffe256a663ced8badb07fdf3ed80e`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 341122
    - Record SHA-256: `9a7b47f826d3942d0456d6951ae3b1dfdebfe05d52705899072aeab9d05d5caa`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-0b4fdddf2e4b53e63493`

- Lineage record SHA-256: `3894e6b2f4f85b21c5d1b23e54a531eacce4178dacc97aec3ba6be590da9c974`
- Source identity SHA-256: `0b4fdddf2e4b53e6349308d8c996f3463f1dabd8881d023ea81cb8b9af9f8684`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 29444
    - Record SHA-256: `f6b24dcad41dce484011650ed2dec84e0bfe05c61811c3cfd37de772a816e83f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-96ce551e762e0448c82f`

- Lineage record SHA-256: `9713ede72bc6e9011dee59e24f625320b632c8f7e6218799c8abee2d83bea0c2`
- Source identity SHA-256: `96ce551e762e0448c82fffa402763a16ffee290f086abecec648983509a544f7`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 74212
    - Record SHA-256: `a7fc3a17d68af296b0ad8aee57efb02ae31b118593da102a867babd2abbcadef`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-7624642585dd765788c0`

- Lineage record SHA-256: `072749a196f49fefc405edef57b9319b2b79b23439c83075d009e09add5d2f47`
- Source identity SHA-256: `7624642585dd765788c0fceadaafceb5b9bf2781c295e7074022c179c3cd91b2`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 1619
    - Record SHA-256: `c1286c6bf37b94f7e3c47dc3c56fba87d59408e146e6777c45b1972c25c65f7f`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-d5c0855ca02a308734e9`

- Lineage record SHA-256: `d601577d62fb5312a73a366cfe6485889d64076e22e0700597955a11f9e5aed8`
- Source identity SHA-256: `d5c0855ca02a308734e96e9da3ba8d8b60ee820176149763eea289ea1b6900dd`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 342205
    - Record SHA-256: `fd662689b64b79512c0b021d14f83f124a19268ff5a9c1674731b45f5ddeec41`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

### Evidence for Case m7-investigation-case-e53d4ce5cfe52727c3046a5a

- Prediction: `m7-prediction-9662acda5c7775e6498c575f`
- Window: `window-central-000e916cc5653eba1d3a`
- M2 window lineage SHA-256: `91299d2e5d434fa7839d55265dcfa5dd0af806b3d8c376e66dac9ccb4291786a`
- M2 window row SHA-256: `d181b7eebfeda27edb44a33f5e9cc502a86eba2e1a7addc94445c5b04576c572`
- M3 evaluation row SHA-256: `47f0f57154fa05c52c983635e03df60b4cd7a7fc70755bc257d022bf9f1ca7d6`
- Source events: 2

#### Event `event-central-ec17d0023f61bb041fb9`

- Lineage record SHA-256: `a5809b8026ff88d08d66ea7de2a3c0bf3faff88921493ca2d21102563ed6ba22`
- Source identity SHA-256: `ec17d0023f61bb041fb910f7808ba7324d92c33fdb607560a3c697c4f41c13dd`
- Source records:
  - `2024-03-24 - 2024-03-31/part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet` row 56483
    - Record SHA-256: `b0f98f4cf5886693577c4d1aa635b5bf63fdec42cf37021e7d138bf56e7c0fe9`
    - File SHA-256: `f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512`

#### Event `event-central-a67360dbb4d70be873f1`

- Lineage record SHA-256: `1f81b9a7c481ed28b77dcb0d8683cdbe3271bc276bc8aebdd5ee2e9756acc70c`
- Source identity SHA-256: `a67360dbb4d70be873f17715f18587c488c7327e1cac65c05f757329da147338`
- Source records:
  - `2024-03-24 - 2024-03-31/part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet` row 7954
    - Record SHA-256: `13f7fd723e0f75a32f294fcc2e240b72babfcc7a1dec04af14efdff55c6a04e7`
    - File SHA-256: `f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512`
  - `2024-03-24 - 2024-03-31/part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet` row 7955
    - Record SHA-256: `04edafb94f83db2eb378f5aea9ba3a23daff4993d024f8eb2db0a012b971fa35`
    - File SHA-256: `f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512`
  - `2024-03-24 - 2024-03-31/part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet` row 7956
    - Record SHA-256: `b8946bfe49f7dcc92e90b5e1ac64e55f2f7773f1b300d565748bdfedfe66c878`
    - File SHA-256: `f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512`
  - `2024-03-24 - 2024-03-31/part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet` row 7957
    - Record SHA-256: `5c7f2ea47431fef8e7d24b2405ce368cd729b00de094b38853bcd5be3796357b`
    - File SHA-256: `f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512`

### Evidence for Case m7-investigation-case-498ee95ed92e641b997528a6

- Prediction: `m7-prediction-fb795dc5ada91e4b831c12e7`
- Window: `window-central-001798b1c92400003e9a`
- M2 window lineage SHA-256: `37fe5f78340c08814ca696f3785dcdba8603dfa78522a1fad61a6387ae5acb41`
- M2 window row SHA-256: `a74e1cbcaf945f8b1d574e9204557295826e6caf73d5df012338489d233c3d64`
- M3 evaluation row SHA-256: `bdbf82c99e5a3affbbe6f0f8a58ecc9e62ca7100e1099658c27622f9c811b254`
- Source events: 6

#### Event `event-central-afccd40f0043ce33bf8f`

- Lineage record SHA-256: `859e9fd8f4ce343938efc09c545addd080b78fb15041f36f821ff8750476f296`
- Source identity SHA-256: `afccd40f0043ce33bf8fa10699219d354b162e96a83f99b0bc0c268520b74b6b`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 323200
    - Record SHA-256: `d015c00dc407f00902e5259cb5029e097ba012a06d8b55c6693277887c32acef`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-5fead349f04ba7bcba04`

- Lineage record SHA-256: `e5471b9279063a0c11990ed7fe9ac35a40daa872a385b1874f8cb2c2fbeae40b`
- Source identity SHA-256: `5fead349f04ba7bcba04b3166bc44d2579f4e1367484e037c0474ef308592537`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 64274
    - Record SHA-256: `0f92d8687a1709fce4fd779ec0f071c485a18e709dcd37948b23be801abff75a`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-334026b284161ed2b7c7`

- Lineage record SHA-256: `bbb0ede96f71703fccf0014b4e2105ebf5d1a46ce22405460fab192b5bcff9ed`
- Source identity SHA-256: `334026b284161ed2b7c7dc460e700e4812487bd5726a10cb9bdc4f7aac5f725a`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 323166
    - Record SHA-256: `09119af31ae7ea35d0f006a4de297f367891c3c550a112c15bfd5c727e29659b`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-e8fa5c9b07fc31ca0d92`

- Lineage record SHA-256: `30dafa3650cf3d07e2e63bd61889914ee8b29324e616e2fc5e06089cfdcd5775`
- Source identity SHA-256: `e8fa5c9b07fc31ca0d925df70bcc7459153f931f308ba04d7e7e2e99ceab66f6`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 73715
    - Record SHA-256: `7fea36db406b26443485e85a87342b6a044d577e75b721ad005985b1a4366529`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-65bd459ee01b3f49a32d`

- Lineage record SHA-256: `158687a099663f0412060553dcbb475d47299aa9182ca87918187d9710fdaf5c`
- Source identity SHA-256: `65bd459ee01b3f49a32ddf7602caa8e6f51284c450e750aa1c392a4873814144`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 73452
    - Record SHA-256: `7786631687741b7a9cfa82d00a30cf3ffcce73b8a5d936c661cec1ee0f8a9761`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`

#### Event `event-central-368fb0b6b28b073bd30b`

- Lineage record SHA-256: `09ef6eab5adbbcf1b7927aefbb19d15ca2be401b994a13d370064173cb067bbe`
- Source identity SHA-256: `368fb0b6b28b073bd30b967a040190e00433f62d0c73875daae097c3925d7052`
- Source records:
  - `2024-03-17 - 2024-03-24/part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet` row 175166
    - Record SHA-256: `24485a17a2e93b9b240ce301075395238eb7e0af8ec1179326e238db77d4b878`
    - File SHA-256: `97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63`
