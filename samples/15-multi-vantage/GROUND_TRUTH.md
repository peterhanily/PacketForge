# GROUND TRUTH — PsExec-style lateral movement to 10.10.0.41

Malicious flows are labelled `atk-*`; everything else is benign ambient noise.

## Kill chain

### Lateral Movement — T1021.002 SMB/Windows Admin Shares / T1570 / T1569.002 Service Execution
- PsExec-style lateral movement to 10.10.0.41: ADMIN$ tool transfer (SMB write of svc.exe) then svcctl CreateServiceW/StartServiceW — the combination BZAR flags.
- Flows: atk-psexec-drop, atk-psexec-svc
- IOCs: attacker=10.10.0.40, target=10.10.0.41, smb_files={"share": "ADMIN$", "name": "svc.exe"}, dce_rpc={"endpoint": "svcctl", "operations": ["CreateServiceW", "StartServiceW"]}, expected_notice=ATTACK::Lateral_Movement_and_Execution

## Indicators of compromise

- `attacker`: 10.10.0.40
- `target`: 10.10.0.41
