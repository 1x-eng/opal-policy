# Role-based Access Control (RBAC)
# --------------------------------

package app.rbac

# By default, deny requests
default allow = false

# Allow admins to do anything
allow {
	user_is_admin
}

# Allow the action if the user is granted permission to perform the action.
allow {
	# Find permissions for the user.
	some permission
	user_is_granted[permission]

	# Check if the permission permits the action.
	input.action == permission.action
	input.type == permission.type

	# unless user location is outside AU
	country := data.users[input.user].location.country
	country == "AU"
}

# user_is_admin is true if...
user_is_admin {
	# for some `i`...
	some i

	# "admin" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "admin"
}

# user_is_viewer is true if...
user_is_patient {
	# for some `i`...
	some i

	# "patient" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "patient"
}

user_is_care_giver {
	# for some `i`...
	some i

	# "patient" is the `i`-th element in the user->role mappings for the identified user.
	data.users[input.user].roles[i] == "care_giver"
}

# user_is_granted is a set of permissions for the user identified in the request.
# The `permission` will be contained if the set `user_is_granted` for every...
user_is_granted[permission] {
	some i, j

	# `role` assigned an element of the user_roles for this user...
	role := data.users[input.user].roles[i]

	# `permission` assigned a single permission from the permissions list for 'role'...
	permission := data.role_permissions[role][j]
}