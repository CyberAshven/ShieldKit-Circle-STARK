# Gate B1 branch-slot:0 target v1

Activated object:

```json
{
  "recordKind": "BRANCH_SLOT",
  "branchSlotId": "branch-slot:0",
  "status": "OPAQUE_UNASSIGNED_NO_CREDIT",
  "relationRef": null,
  "relationSemanticsId": {
    "status": "UNASSIGNED",
    "value": null
  },
  "authority": "NONE",
  "credit": "NONE"
}
```

This is an opaque, package-local allocation of `branch-slot:0`. `branch-slot:1` remains unmaterialized. The allocation conveys no priority, semantic meaning, or exhaustiveness.

The accepted trigger remains immutable with status `PROPOSED_NO_CREDIT` and an empty `affectedBranchSlotIds` list. This target grants no downstream authority or credit.
