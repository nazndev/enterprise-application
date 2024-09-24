-- 1. Check all users and their roles
SELECT
    u.id AS user_id,
    u.username,
    r.id AS role_id,
    r.name AS role_name
FROM
    users u
JOIN
    user_roles ur ON u.id = ur.user_id
JOIN
    roles r ON ur.role_id = r.id;

-- 2. Check all roles and their API permissions
SELECT
    r.id AS role_id,
    r.name AS role_name,
    ap.id AS api_permission_id,
    ap.api_path,
    ap.microservice_name
FROM
    roles r
JOIN
    api_role_permissions arp ON r.id = arp.role_id
JOIN
    api_permissions ap ON arp.api_permission_id = ap.id;

-- 3. Check all policies and their associated API permissions
SELECT
    p.id AS policy_id,
    p.resource_name,
    p.action,
    ap.id AS api_permission_id,
    ap.api_path
FROM
    policies p
JOIN
    policy_api_permissions pap ON p.id = pap.policy_id
JOIN
    api_permissions ap ON pap.api_permission_id = ap.id;

-- 4. Check all policies and their associated actions and resources
SELECT
    p.id AS policy_id,
    p.resource_name,
    p.action,
    a.name AS action_name,
    r.name AS resource_name
FROM
    policies p
JOIN
    policy_action_resources par ON p.id = par.policy_id
JOIN
    actions a ON par.action_id = a.id
JOIN
    resources r ON par.resource_id = r.id;

-- 5. Check all roles and their associated policies
SELECT
    r.id AS role_id,
    r.name AS role_name,
    p.id AS policy_id,
    p.resource_name,
    p.action
FROM
    roles r
JOIN
    role_policies rp ON r.id = rp.role_id
JOIN
    policies p ON rp.policy_id = p.id;

-- 6. Check all users and their attributes
SELECT
    u.id AS user_id,
    u.username,
    ua.attribute_name,
    ua.attribute_value
FROM
    users u
JOIN
    user_attributes ua ON u.id = ua.user_id;

-- 7. Check all API permissions and their associated roles
SELECT
    ap.id AS api_permission_id,
    ap.api_path,
    r.id AS role_id,
    r.name AS role_name
FROM
    api_permissions ap
JOIN
    api_role_permissions arp ON ap.id = arp.api_permission_id
JOIN
    roles r ON arp.role_id = r.id;


