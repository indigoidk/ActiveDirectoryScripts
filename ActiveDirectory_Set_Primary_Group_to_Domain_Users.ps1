# !!!!!!!!!!!!!!RUN AT YOUR OWN RISK!!!!!!!!!!!!!!
# 1/18/24 - Changes Primary Group back to Default of Domain Users; preventing the Primary Group attack
# !!!!!!!!!!!!!!RUN AT YOUR OWN RISK!!!!!!!!!!!!!!
# Run as powershell active directory as administrator/ sufficent rights
# Powershell defines the domainUsersVariable
# Add Domain User group to the user(s)
# Set's the Primary Group to the variable / "Domain Users" AD Group
# Source:
# https://www.tenable.com/blog/primary-group-id-attack-in-active-directory-how-to-defend-against-related-threats
# https://www.semperis.com/blog/ad-security-101-primary-group-ids/
# https://www.qomplx.com/blog/primary-group-id-attacks/



# Get the "Domain Users" group object
$domainUsersGroup = Get-ADGroup "Domain Users" -Properties "primaryGroupToken"

# Find users whose primary group is not "Domain Users"
$users = Get-ADUser -Filter * -Properties PrimaryGroup | 
         Where-Object { $_.PrimaryGroup -ne $domainUsersGroup.DistinguishedName }

foreach ($user in $users) {
    # Add user to the "Domain Users" group
    Add-ADGroupMember -Identity $domainUsersGroup -Members $user

    # Change the user's primary group
    Set-ADUser -Identity $user -Replace @{primaryGroupID=$domainUsersGroup.primaryGroupToken}
}