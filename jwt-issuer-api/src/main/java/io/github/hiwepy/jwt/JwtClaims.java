/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.github.easy4j.jwt;

/**
 * Constants for standard JWT claim names used in user authentication and authorization.
 * These claims are typically included in the JWT payload to carry user identity and authorization information.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class JwtClaims {

	/** Default role assigned when no role is specified */
	public static String DEFAULT_ROLE = "guest";

	/** User descriptor ID */
	public static final String ID = "id";
	/** User ID (source table ID) */
	public static final String UID = "uid";
	/** User UUID (unique user identifier) */
	public static final String UUID = "uuid";
	/** Username */
	public static final String UNAME = "uname";
	/** User key: unique ID in the user business table */
	public static final String UKEY = "ukey";
	/** User code: unique code in the user business table */
	public static final String UCODE = "ucode";

	/** Role ID (role table ID) */
	public static final String RID = "rid";
	/** Role key: unique ID in the role business table */
	public static final String RKEY = "rkey";
	/** Role code: unique code in the role business table */
	public static final String RCODE = "rcode";
	/** User password salt: used for password encryption/decryption */
	public static final String SALT = "salt";
	/** User secret key: used for JWT encryption/decryption */
	public static final String SECRET = "secret";
	/** List of roles assigned to the user */
	public static final String ROLES = "roles";
	/** List of permission markers for the user */
	public static final String PERMS = "perms";
	/** User profile data */
	public static final String PROFILE = "profile";
	/** Whether the user has bound additional information */
	public static final String BOUND = "bound";
	/** Whether the user has completed profile information */
	public static final String INITIAL = "initial";
	/** Whether the user requires multi-factor authentication */
	public static final String VERIFY = "verify";
	/** User's latest longitude coordinate */
	public static final String LONGITUDE = "longitude";
	/** User's latest latitude coordinate */
	public static final String LATITUDE = "latitude";
	/** Request parameter signature */
	public static final String SIGN = "sign";
}
