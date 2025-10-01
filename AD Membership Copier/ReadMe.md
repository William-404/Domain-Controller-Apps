## What it does
Copies direct group memberships only (security + distribution).
Excludes primary group (e.g., Domain Users).
Adds missing groups to the target user without removing anything from either user.

## How it works:
Resolves users via sAMAccountName, UPN, DN, or partial first/last name using ANR.
Displays an inline dropdown for multiple name matches.
Reads direct group memberships with an LDAP member= query.
Uses Add-ADGroupMember on the PDC Emulator DC for consistency.
Requires an account with rights to add members to the relevant groups.


## Quick Start
1. In Copy From, start typing a username, first name, or last name.
2. If there’s one match, click Load user to load immediately.
3. If there are multiple matches, the dropdown opens - pick the exact person (full name).
4. The From user panel fills with that user’s direct groups.
5. In Copy To, repeat the same search/pick flow for the target account.
6. Click Add permissions.
7. A confirmation shows the exact groups to be added (only those the target doesn’t already have).
8. Choose Yes to proceed.

The To user panel refreshes with the updated memberships, and a status line confirms how many groups were added.

Please Note this requires ADWS to be Active
