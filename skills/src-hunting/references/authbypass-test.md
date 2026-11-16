# authbypass-authentication-flaws

If what opens is a login page / SSO → the form shell follows `dig-scope` §4.1.1: find the business surface; do not run dictionaries / captchas / unlimited password guessing from this file start to finish.  
Session issuance, reset, rebinding, ticket exchange and 2FA are probed per this file + `dig-scope` §4.2.2 — do not skip the whole lot because of §4.1.1. The table is the per-site floor, not a licence to only fire these shots.  
Middleware bare-default endpoints are visible at a glance. Slider / code sending / password guessing without a valid account → switch to the auth chain, do not stop halfway. Whether to write a report is governed solely by `vuln-report-format.md`.
The English dictionary / 20 captcha methods / reset matrix have been cut; search short-table pointers by heading. Host-poisoning reset is in `http-host-header-test.md`. QR-code login CSRF is in `csrf-test.md` §18.

# Authentication Bypass

### Unauthenticated password-change endpoint

Recognize: password change / first-time password set / the last reset step can be reached without login. The body commonly has an old-password or verification-code field (`old_pwd` / `sms_code` and the like) + the new password + an identity id. The official page says SMS/old password is required, but the endpoint may still accept an empty string.

Hit: without login. Leave the old password/code empty or omitted and make the new password pass complexity. Control: a wrong verification code should be blocked; a nonexistent identity id should return nothing. If the same password again reports "duplicate of a historical password" = it has already been written to the database, not an empty success. Revert immediately once it passes; if you cannot revert, stop — do not switch to another person and do not log in.

Out: unauthenticated Success, and someone else's password is changed.

False positives: only returns 0 without writing to the database; a real old password/real SMS is required; Success but login goes through a different IdP and the password never propagated.

### IDaaS unbound security questions

Recognize: IDaaS forgot-password. Submitting a username anonymously issues a JWT with `scope` = `_` (not reset). The security-question bank ids are enumerable; writing an id already bound to that account returns 409. The common IDaaS wrapper path is `forget_password/v2/sq`; hit the same shape under other wrappers.

Hit:

1. Without login POST sq with body `{"username":"admin"}` (or an account first confirmed via the existence endpoint).
2. GET question with the token and note the already-bound ids.
3. POST `update_question` to write the answer for an **unbound** id (do not force-write a bound id).
4. `verifyquestions?type=RESET_PASSWORD` with your own three questions, exchanging for `self.password.expired.reset`.
5. `set_password`: revert immediately once it passes; if you cannot revert, stop at the response and do not leave the admin password changed. If policy rejects and the security question was not written → half a link, do not enter it in the table as broken.

Out: security-question answers written onto someone else's account (rebinding), or the token really changes someone else's password.

False positives: the sq token sent straight to set_password reports `scope is not expected`; you can only write an already-occupied question and get 409; verify with a wrong answer; policy rejects and the security question was not written. If a single site misses, do not delete this row from the short table.


### Unauthenticated training bind endpoint (short-table pointer)

Recognize: the training / academy H5 gateway puts account binding and query RPCs under an unauthenticated client prefix (`/spapi/v2/client/` and the like). The body takes a consumer uid (`mtUserId`) + merchant number (`bAccountId`), no Cookie.

Hit (no login):

1. POST bind: swap the uid to someone else, the merchant number to one you made up  
2. POST querybind: with only the uid, or only the merchant number  

Counts as: the other party's phone comes out, or the bind succeeds and rebinds.

False positives: only returns not-logged-in / parameter error; the uid is always unbound with no phone and cannot be written. If a single site misses, do not delete this row from the short table. Real key material and any particular phone number do not go into the knowledge base.

### Federated login only takes uin (short-table pointer)

Recognize: the cloud activity / hackathon / partner portal issuance endpoint's body has only `provider` + a cloud account `uin` (or similar uid) and does not verify the OAuth `code` / `ticket` / `id_token`. A public list or by-code lookup can reveal someone else's UIN.

Hit (no login):

1. Copy a `uin` from the public partner/user list, or hit by-code first  
2. `POST` the issuance endpoint with only `provider` + the other party's `uin`  
3. Use the JWT against `me` / user info  

Counts as: me is the **other party's** UIN and you can act as that account. Only an empty guest account → not a hit.

False positives: a real OAuth code is required; an unregistered uin is rejected outright; the ticket is issued but me is still you. If a single site misses, do not delete this row from the short table. Real key material and any particular JWT do not go into the knowledge base.

### Activity lab login does not verify the federated ticket (short-table pointer)

Recognize: the activity page login takes a federated `openid`+`acctype`+`access_token` and the server **does not go to the identity provider to verify** the ticket. Control gate: with the same parameter set, `acctype=wx` or an empty `access_token` fails login, while `acctype=qq`/`qc`/`pt` plus a fake token still issues a ticket. This is not the generic empty-password/omit shot, nor the cloud-activity-only-takes-uin row. The frontend `fx_act_helper.js` / Milo login helper is a common wrapper; hit it even without those names.

Hit (no login):

1. POST `/api/login` (follow the page for the activity prefix, do not pin one path), with `access_token` fake, `acctype` = qq (then one shot each for qc/pt), `openid` an enumerable number  
2. Use the JWT against getRoles (by region/server) / bindRole-style role endpoints. Control: without the header it should require login; wx/empty ticket should fail  
3. If the role list is empty, do not assume no bug — switch region/server and neighbouring ids; follow the bind endpoint until it binds, then stop. If it passes and you can revert, revert  

Counts as: the ticket carries the other party's openid, their role names/`charac_no` appear in the role list, or you can bind to them.

False positives: only an empty account is issued with a fully empty role list and no game character can be bound; a real federated ticket is required. Real key material and any particular JWT do not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Session ticket inside an operations-config deep link (short-table pointer)

Recognize: a home page / operations-config JSON reachable without login whose banner jump URL (skipPath / jumpUrl / schema) carries `token` / `apptoken` / `access_token` in the query — a string usable as a session. Control gate: calling me without this string should report an expired login.

Hit (no login):

1. Copy the whole jump URL from the config and put the ticket from its query into the Token / Authorization header  
2. Hit me / user info / wallet  
3. Control: the same endpoint without the string should be expired  

Counts as: me is someone else's phone/role and the session can act as that account.

False positives: the ticket is expired or a placeholder and cannot log in; the config only has marketing copy with no ticket. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Signature verification failure 302 leaks the computed signature (short-table pointer)

Recognize: the payment/open gateway envelope has `sign_data`/`sign` + a merchant number. With a fake signature **GET / DELETE / OPTIONS / HEAD may all 302**, with the Location or `msg` carrying the valid signature the server just computed (`calculateSign is:` and the like). Some gateways only return HTML/ILLEGAL_SIGN on GET and leak only when the METHOD changes; some gateways **leak on GET itself** — do not only try DELETE/OPTIONS.

Hit (no login):

1. Send a fake signature to the signing/order endpoint and **check Location on GET first** for `calculateSign`  
2. If GET does not carry the signature, switch to DELETE/OPTIONS/HEAD and copy the signature from the decoded Location URL  
3. Put it back into `sign_data` and hit the query/order endpoint. Control: a fake signature still fails, a real signature returns their merchant order  

Counts as: passing signature verification reveals **another merchant's** unpublished order/account body (amount, close reason, card type).

False positives: every METHOD only reports a signature verification failure with no computed signature; copying it back is still rejected. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Identity-provider proxy error echoes the token (short-table pointer)

Recognize: a business endpoint calls the identity provider on the frontend's behalf. Three common wrappers: ① a mini-program code / jump-code endpoint where you control `path`/`page`/`pagepath` and an illegal page makes the message echo `access_token=` verbatim; ② a QQ/OAuth ticket-exchange endpoint that concatenates `client_secret` into the upstream URL, so changing `redirect_uri` to an external domain makes the downstream return HTTP 5xx and the error URL spills `client_secret=` to the frontend; ③ an unauthenticated business endpoint `GET /api/business/access-token` (or a similar ticket path) that returns 200 with the ticket directly, no need to wait for an error echo. A fake code sent to the local callback often only returns a business error code without the key — **do not stop**. If the list contains a ticket endpoint, do not only hit the code-issuing endpoint.

Hit (no login):

1. If the list has a ticket endpoint, GET it first; if 200 and `data` is an `access_token`, treat it as already copied — no need for the illegal pagepath  
2. Without a ticket endpoint: fill `path` with an external site or an obviously illegal page; for the ticket-exchange endpoint, first compare a fake code with a local `redirect_uri`  
3. Then change the exchange endpoint's `redirect_uri` to an external domain and copy `access_token=` or `client_secret=` from the error URL/message  
4. Use the identity ticket against `<identity-provider API>/cgi-bin/account/getaccountbasicinfo`, then `/wxa/generatescheme`; use the QQ AppSecret to exchange an authorization code for that app's access_token / hit the site's ticket exchange  

Counts as: the official account subject/appid can be queried, or an official jump code is issued; or the full AppSecret can be exchanged for that app's access_token.

False positives: the error only has an ErrCode with no token/secret; a fake code to the local callback carries no key; the token is invalid against the identity API; the secret cannot be exchanged for a ticket. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Activation page RPC hands out signKey (short-table pointer)

Recognize: payment UISDK / activation page. Hit the config or thrift endpoint without login with only an enumerable `appId` in the body. A dead app returns `APP_NOT_FOUND` with no key; a live app returns the full `signKey`/`signMethod`. This is not the hard-coded-in-docs/webpack shot (that is the next section).

Hit (no login):

1. Swap `appId`. Control: a dead number should have no key  
2. Copy the live number's `signKey` and sign on the spot using the returned `signMethod` (commonly MD5, parameters concatenated in dictionary order with `&key=`)  
3. Hit the payment query. Control: a fake key gives `SIGN_ERROR`, a real key passes  
4. Do not stop at the query once it passes. Hit the settlement-card change `change/card`: differential the branch number to get a `changeId`, and only count it if the original value reports unchanged. SUCCESS but `changeId=null` / the fee rate unchanged does not count. Revert immediately once it passes  

Counts as: a full AppSecret that really passes production signature verification; or querying another merchant's ID card/card/pending order; or creating a virtual store poiId; or changing another merchant's settlement card/bank (with a `changeId`).

False positives: a placeholder key that fails verification; both live and dead return `APP_NOT_FOUND` with no key. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Debug docs hard-code the AppSecret (short-table pointer)

Recognize: docs / Demo / official packages / onboarding HTML / historical npm packages hard-code a **complete** AppSecret (appId+appSecret, signKey, merchant pfx, SDK key) — not a `your-secret` / `YOUR_ACCESS_KEY` placeholder. **The wiki may mask the key with asterisks while the same official zip / Demo / HTML sample is still plaintext — do not stop. Do not treat an old npm version as delisted.** Common wrappers: a debug guide's `config.js`, the GitHub `properties` an FAQ links to, a documentation screenshot PNG, `prod/config.properties` / Demo Java `baseInfo` inside an SDK zip, an onboarding HTML's `MSDKConfig.json`, a public npm `index.js`. Nearby there is usually a ticket-exchange endpoint or a production endpoint that can be signed per the docs. Where to hit the algorithm is below; do not pin one vendor.

Hit (no login):

1. Copy appId/accessKey and appSecret/secretKey from the docs, from a GitHub link reached via the FAQ, **or from an operations screenshot on the docs page** (real values go only into the report, never this knowledge base). OCR/read the screenshot; do not stop at config.js
1b. Enterprise IM / open directory: if `user/get` or `user/list` returns an empty mobile after exchanging the ticket, **do not stop** — hit `linkedcorp/user/get` (body `userid`). Control: the directory endpoint has no phone and the federated-enterprise endpoint returns an 11-digit phone — only then is the chain escalated
2. Ticket exchange: put a fake string in `code`. Control: an equal-length fake secret should give "invalid business parameter", a real key gives "authorization code expired/invalid code". If the site has no `/proxy` and the ticket endpoint lives on another business domain, POST `grant_type=client_credentials` directly to the same product's standalone oauth `/oauth/v2/token` (control: a fake key gives `invalid_client`)
3. Distribution/open query endpoints: HMAC per the docs (keys concatenated in lowercase dictionary order; if there is a `test=test`-style integration parameter, include it). Control: a fake secret fails the signature, a real key returns the supply roster under that app
4. Official CLI debug/release package endpoints (`package/changeDebugVersion`, `changeVersion` and the like). Control: a fake key gives "key error"; a real key passing auth and turning into "game package resource does not exist" also proves the key is live — do not stop because no real package was uploaded. **Do not only hit upload/version change on the package endpoint**; also hit WASM subpackage `packageBind` / `build` / `queryBuildResult`; a fake key giving a key error and a real key binding under that app counts as written
5. If the gateway has a server IP allow-list: try `X-Forwarded-For: 127.0.0.1`. Without the header it should be unauthorized; with it the real key returns supply
6. After the supply query passes, do not stop at the roster: hit the pre-order check, then booking with the returned sell price/settlement price. Control: a fake key fails the signature. Cancel immediately once an order number is produced; if you cannot revert, stop at the response; batch real orders are forbidden
7. Public GitHub/SDK RSA+3DES demo: if the production XML pay-gate still accepts it, sign on the spot and `POST /service/query` to decrypt the returned ciphertext. Control: a fake key fails verification. If a neighbouring number shares the same demo RSA, a business error (bad order number) is not a signature failure — the key is still live. Real orders/refunds are forbidden
8. An object-storage long-lived presigned SDK zip in the open docs: unpack `prod/config.properties` (plus the national-crypto config) and the pfx, open the certificate with the configured password, copy the merchant number/signKey and hit the **production order query**. Control: a fake key gives SIGN_ERROR. Query only; real transfers are forbidden
9. Game MSDK: when wiki encode=2, `sig=md5(msdkKey+timestamp)` (not bound to path/body, no time window) — sign against production/test `/auth/*`. Control: a fake signature gives `sig error`; a real one passing the gate and turning into an identity-provider `access_token expired` / handQ `0x711` business error also proves the key is live — do not treat it as no bug. V3 `/auth/guest_register`: a plaintext uuid `reqid` gives `decrypt faild`; use the **first 16 ASCII characters** of msdkKey as the QQ TEA key (16 rounds big-endian `oi_symmetry_encrypt2`) then hex; once a guestid is issued hit `/auth/guest_check_token`. If there is no valid social token for a player, stop; grinding login to enter an account is forbidden
10. Official onboarding HTML sample `MSDKConfig.json` plaintext `MSDK_SDK_KEY`: with `source=0`, `sig=md5(path+"?"+dictionary-ordered query excluding sig+body+key)`; decrypt with `md5(ts+ciphertext+key)` (once the doc's sample ts/ciphertext/signature line up, take it to production). Control: a fake signature gives `invalid sig`; after a real one passes the gate, hit guest login — if `channel_info` with only a made-up uuid still issues openid/token/jwt, that counts as a user ticket. Grinding channel codes to enter someone else's account is forbidden
11. Historical npm package hard-codes `developerId`+`signKey`: on the partner-centre gateway a fake signature with a live number returns "signature error" and a dead number returns "developer data abnormal", so live numbers are enumerable. Real signature is `sign=SHA1(signKey+sorted key+value pairs)`. The privacy-number bulk pull endpoint returns `OP_SUCCESS` even without the store `appAuthToken`; a ticket-exchange endpoint whose real signature passes the gate and turns into "onboarding status incorrect" also proves the key is live. An empty array is not a false positive (no downgraded orders right now). **Do not stop**: a higher version of the same npm set hard-codes `appAuthToken` — do not dismiss it as integration config; sign on the spot with the token against `queryPoiInfo`, swap `ePoiId` to get another merchant's store name + 11-digit phone. Real orders / grinding authorization codes are forbidden
12. Recharge/enterprise-payment Demo HTML (`enterprise_client` and the like) with AppId+AppKey hard-coded in inputs: do not dismiss it as an integration placeholder. Copy it without login, build the HMAC-SHA1 source string `GET&urlencode(path)&urlencode(key-sorted kv)`, key `AppKey+'&'`, Base64 to get sig. Control: a fake signature gives `sig error`. A real one against production `/v1/r/{appid}/open_order` returns a `token_id`. Create unpaid orders only; paying via the cashier/refunding is forbidden. Real values go only into the report
13. Login-page JS writes the DingTalk ISV `suiteKey`+`suiteSecret` as `clientId`/`clientSecret` (values start with `suited`): do not dismiss it as an OAuth placeholder. Without login POST `https://oapi.dingtalk.com/service/get_suite_token` with a fake `suite_ticket`. Control: a fake secret returns "illegal suite key or secret". A real key returns `suite_access_token`. Real values go only into the report
14. Console webpack/Vuex default map key: do not dismiss it as a placeholder. After the fake-key control, do not only hit reverse geocoding: hit the place-cloud/layer `table/list`, then `data/list` for any table. Only reverse geocoding works and the tables are empty → false positive. Real values go only into the report
15. Official docs/onboarding HTML sample curl hard-codes the Gamekey: do not dismiss it as a placeholder. Without login copy AppID+Gamekey, sign `sign=md5(mod,func,appid,time,postdata,key)` against the production queue gateway `getZoneListCount`. Control: a fake key gives `req sign error`. A real signature with `ret=0` returns zone/server online counts. Query queue/online only; inserting people into the queue and removing people from the queue are forbidden. Real values go only into the report

Counts as: the key is live and can be exchanged for that app's user ticket, or a business query returns the supply roster under that app, or a WASM subpackage version can be bound to that app, or booking produces an order number for that app, or it decrypts **another merchant's** unpublished payment order cardholder; or a fake signature fails verification while a real one passes the production gate and turns into a downstream identity-provider business error (proving production still accepts this complete key); or production `open_order` returns an unpaid `token_id`; or DingTalk `get_suite_token` returns `suite_access_token`; or the production queue `getZoneListCount` returns `ret=0` with zone/server online counts.

False positives: the docs contain placeholders; real and fake keys produce the same error; the key is expired and cannot connect; the integration key only works against the test environment and production rejects it; the wiki is masked so you assume the zip/Demo is masked too. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Portal CMS hard-codes the site key (short-table pointer)

Recognize: the portal/open-platform frontend (not a debug-doc zip) hard-codes the portal CMS's `accessKey`+`secretKey`. There is `GET /api/v1/cms/login` returning a JWT, commonly in a `cms-token` header. The home page may just be the CMS welcome page while the key lives in another portal JS file.

Hit (no login):

1. Copy the AK/SK and hit login (real values go only into the report)
2. With the ticket hit `channel/list`, `content/list|detail|search`, `attachment/list`
3. Do not stop at the official-site carousel channel. Follow developer/test/backend channels and GET `attachments.url`

Counts as: internal test reports / the body of articles in channels not shown publicly (xlsx sheet fields count too).

False positives: only public marketing Banners/client download links. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Signature nonce is the private key (short-table pointer)

Recognize: the enterprise IM/business **unlogin** signature endpoint (`queryAppSignature` / `queryCorpSignature` and the like). Other business endpoints demand login; this one does not want a Cookie. The returned `nonceStr`/`nonce` starts with `MIIE` or `-----BEGIN` and can be loaded as a PKCS8 private key. There is commonly an unauthenticated channel/live-code endpoint before it leaking `corpId`.

Hit (no login):

1. Copy `corpId` from the unauthenticated channel/live-code endpoint  
2. POST the signature endpoint with url + corpId  
3. Load `nonceStr` as a private key (Python `load_der_private_key` / openssl). Control: a fake corpId should be a business error with no PEM  

Counts as: it loads as an RSA private key.

False positives: the nonce is only a short random string; a fake corpId always gives a business error. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Unauthenticated IM/trial ticket issuance (short-table pointer)

Recognize: unauthenticated `im/getConfig` hands out a TIM `userSig` with `identifier=null`; or a cloud-product experience centre/apaas signature endpoint issues a ticket for the **existing userId** in the request (control: a guest `none_auth` opens a new account); or other business endpoints on the same backend demand login while the signature endpoint issues an IM/RTC userSig given only a custom trace header + a client-supplied userId; or a self-built IM gateway signature endpoint takes only appkey, the ticket has no userId, and the identity is the uId in the onboarding body; or a JS-written v2 inner signature is behind an IP allow-list; or the official audio-video/IM Web Demo frontend hard-codes the signature endpoint and a fixed pwd, the identifier follows the request, and an empty password still issues a ticket for an existing user.

Hit (no login): use the sig to log into the **IM access domain**: `openim/login`, `getmsg`, `friend_get`, `get_joined_group_list`, group profile/messages. On the trial page also hit login_token and check `data.phone`. Control gates: other business endpoints should demand login; add only the trace header to the signature endpoint and swap userId to interviewer_/candidate_; use the authorization/signature against group history/joining a room. After an anonymous appkey issues a ticket, swap the uId in access/get to interviewer_/admin and check the userID in the response. If v2 `by_app_name` returns IP not allowed, **do not stop** — switch to v3 on the same path, which only needs `appName`. Official Demo: copy the UserSigService URL and pwd from JS, fill identifier with an existing user number; send one more shot with an empty pwd. Use the userSig against friend_get and control against an empty guest account.

Counts as: pulling **other people's** conversations/group members/friends, or plaintext phones.

False positives: you can only log in as the guest `null`, empty conversations, only empty groups you created; swapping to someone else's UserID gives 70013; `none_auth` only opens an empty account; a demo account with no bound phone does not count. If a single site misses, do not delete this row from the short table.

### Hard-coded product number issues a shared JWT (short-table pointer)

Recognize: an AIGC/utility H5 or landing page hard-codes the product number / `qbid` in the script. The signature endpoint (`account/qb` and the like) issues a **shared product-number** JWT without login, and the ticket's name is the product name rather than a guest. JS often only has create / GET by id and no list.

Hit (no login):

1. Copy the page's hard-coded product number and hit the signature endpoint  
2. With the ticket, POST the same-origin `.../task/list` (or a workflow/history list the JS does not mention). Control: without the ticket it should be not-logged-in; an empty-body list still returns total  
3. Follow `userImages` / the original-image CDN and confirm real faces/ID photos download  

Counts as: list total is huge and carries **other people's** original images/ID photos.

False positives: the ticket can only create empty tasks; list total=0 or only what you just uploaded. Real key material and any particular JWT do not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Official support chain issues an external-site link (short-table pointer)

Recognize: enterprise support H5 issuance chain; the inline JS has `getXcxLink`/`get_wx_open_link`. This is not a generic redirect page.

Hit (no login): POST `queryStr=caUrl=<external site>&urlType=2`. Open the returned `support landing link`.

Counts as: the landing page's formal name is the official support account, and the query decoded by `base64Decode` is the URL you supplied.

False positives: only this site's `/ca/` is issued; the landing page carries no query; login is required. If a single site misses, do not delete this row from the short table.

### Demo account claims cloud keys (short-table pointer)

Recognize: cloud-vendor product Demo / trial page / console proxy / supplier backend; claiming STS, federated identity or creating tasks needs only a business id or an empty body, no Cookie. The STS endpoint reporting only field validation (not a login gate) when parameters are missing does not necessarily mean a demo account exists. This is not the object-storage STS wildcard overwrite (that shot is in `file-upload-test.md`).

Hit (no login): if there is a demo account, copy the customer number and then hit claim-key / create-task / federated identity. Without a demo account, still hit the claim-key endpoint: missing parameters reporting field validation is not a login gate. An empty body reporting missing `AppId`/`Uin` is also not "no endpoint" — a parseable numeric Uin may still issue a federated STS; bucket+file_name is still worth hitting. The claim-key endpoint may live under an independent demo CDN's `/openapi/` (follow the page JS). After the share-domain frontend passes HMAC through the gateway, compare against other endpoints' "token invalid / Token verification failed"; still hit the `/share/token/info`-style STS endpoint without the share-page token. Probe bucket liveness by swapping the bucket and looking for PUT/NoSuchBucket. Take the key to GetCallerIdentity against the main account; if there are actions like start/retrieve, sign again (if the quota is insufficient do not stop — see whether you can at least query the account or produce a bill). After Epaas passes the HMAC `SC-SIGN`, the roster still says UserNotLogin — look specifically for GetUploadURL/FileName that do not verify the token (passing the signature ≠ returning data).

Counts as: the temporary key can query the AccountId/role name; the list under the same identity shows the task you just created; or the retrieve output returns bills/instances/another subject's business fields; or a live bucket PUT returns 200.

False positives: the key is Unauthorized on every business API; the claim-key endpoint demands login/401; create returns 200 but the list has nothing. Having no demo account/customer number is not a false positive. If a single site misses, do not delete this row from the short table. Real key material does not go into the knowledge base.

### Unauthenticated issuance of a partner login link (short-table pointer)

Recognize: the e-contract / supplier portal a human opens is a login page whose only input is an enumerable partner numeric id (partnerId / supplierId and the like) with no password. Unauthenticated `getUrl` (or a similar login-link issuance) returns `partnerId`+`generate`+`code` directly. Nearby there is `setCookies` / a ticket-exchange endpoint that takes these three items to obtain a session.

Hit (no login):

1. Copy the issuance endpoint from the login page JS, using the numeric partner id hinted on the page or a neighbouring number  
2. POST the three returned items to setCookies / the ticket-exchange endpoint and copy the Set-Cookie  
3. With the session hit the contract list / payment onboarding / identity endpoint. Control: without a Cookie it should be not-logged-in; a nonexistent partner id should return nothing  

Counts as: the identity endpoint reports a successful login, or you can act as that account to read unpublished contracts.

False positives: the issuance endpoint requires being logged in; the code must be opened from an email; setCookies does not yield a session; only the public recruitment page comes out. If a single site misses, do not delete this row from the short table. Real key material and any particular Cookie do not go into the knowledge base.

### Unauthenticated partner direct-connect config query (short-table pointer)

Recognize: the operations console / supply-chain frontend exposes the supplier direct-connect config query as unauthenticated. The body has only an enumerable partner numeric id (partnerId and the like), no Cookie. The response's `partnerInfos` (or similar) carries clientId+clientSecret.

Hit (no login):

1. Copy the query endpoint from the operations console JS (getV2 / tech/partner and the like)
2. Use neighbouring partnerId values. Control: an unconfigured id should return nothing/not configured, not a login gate
3. Verify it is a complete clientSecret, not an empty success code

Counts as: the response contains a complete clientId+clientSecret usable as this direct-connect key.

False positives: the endpoint is offline; clientSecret is empty or a placeholder; login is required; only the company name comes out with no key. If a single site misses, do not delete this row from the short table. Real key material does not go into the knowledge base.

### Unauthenticated issuance redirecting to an external domain (short-table pointer)

Recognize: unauthenticated SSO/redirect issuance; the callback only checks whether the string contains the official host, or performs no check at all and any external domain can be signed.

Hit (no login): fill callback/redirect with an external domain — try both embedding the official host (query/subdomain/userinfo) and **not** embedding it. If the response has a ticket/signature, hand it to your own SSO. On the passport page, see whether it does `location.replace(redirect+"?"+tokenName+"="+session)`. Control: a string without the official name should be blanked or blocked. If a ticket is only issued after a real-device login and the frontend never concatenates the token into the redirect → half a link; stop at the signed order and do not count it as broken.

Counts as: SSO succeeds and the redirect is still an external domain; or after login the passport appears in an external domain's query.

False positives: the callback is blanked; SSO is missing a callback parameter. If a single site misses, do not delete this row from the short table.

### Missing parameter: move the field to a header and get a ticket (short-table pointer)

Recognize: an unauthenticated business endpoint's JSON reports "missing xxx"; it still reports missing after the parameter is supplied in query/body. Or Spring returns 400 HTML/`message` saying `Required String parameter 'os' is not present` and the name it cites is a **Cookie name**, not a query parameter.

Hit: put this field in an **HTTP header** and hit SSO/ticket-exchange/login again. If the header is not accepted, do not stop — switch to a Cookie (device `uuid`/`os`/`platform` and the like, made up by you). Try unauthenticated write endpoints (bind store / change status) the same way; do not only hit ticket exchange. Control: with it only in query it should still report missing.

Counts as: someone else's login ticket/name comes out; or you write onto another person's store/object.

False positives: the field is in query and it still reports missing (neither header nor Cookie accepted) — that does not count as passed; only your own ticket comes out. If a single site misses, do not delete this row from the short table.

### Password login endpoint behind an SSO shell (short-table pointer)

Recognize: the admin backend a human opens only redirects to SSO / unified auth and the page has no username/password box, yet the backend still exposes a password login API. Do not treat the SSO shell as the whole surface having no login endpoint. The common admin skeleton `/admin-api/system/auth/login` is a frequent wrapper; hit it even without that name.

Hit (no login):

1. POST `/admin-api/system/auth/login` with body `{"username":"admin","password":"123456"}` (do not grind SSO captchas)
2. Put `data.accessToken` into `Authorization: Bearer` and hit `/admin-api/system/tenant/page` or `/system/user/page`
3. Control: a wrong password should fail; the default endpoint returns a platform ticket with `userId=1` and the like

Counts as: you enter the platform admin account and the tenant/user list returns other people's phones/names.

False positives: the login endpoint 404s or the default endpoint has been changed; the ticket only enters an empty tenant with no contacts. Real key material and any particular Token do not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Refresh-ticket empty body issues an admin ticket (short-table pointer)

Recognize: the JSON gateway has a refresh-ticket endpoint (`/api/auth/refresh` and the like). Without login, an empty body `{}` issues a ticket whose identity is `admin` (not a guest). The admin backend and the frontend share the same cloud-development/gateway.

Hit (no login): POST the refresh endpoint; put `data.token` into `Authorization: Bearer` and hit `/api/admin/me/permissions` plus the application/user roster. Control: without this ticket it should be not-logged-in.

Counts as: me is a super administrator (permission `*`), or the roster returns **other people's** phones/names.

False positives: only a guest/expired ticket comes out; refresh requires an old refresh token; me is still you. Real key material does not go into the knowledge base. If a single site misses, do not delete this row from the short table.

### Empty openId enters an existing account (short-table pointer)

Recognize: the mini-program / H5 GET login endpoint takes `openId` (`loginByOpenId` and the like). A missing parameter reports a missing field, a fake openId fails login, but an empty string still returns 200 with an **existing merchant account** and phone — not an empty guest account.

Hit (no login):

1. One shot with the parameter missing, to confirm this is the login endpoint  
2. One shot with a fake value, which should fail  
3. Hit again with `openId=` empty; if GET query is not accepted, try POST JSON `{"openId":""}`  
4. Control: the store name/login phone from the empty string versus the fake value failing and the missing parameter erroring are not the same guest account  

Counts as: you enter an existing merchant account and a phone comes out (you can act as that account).

False positives: the empty string only returns an empty guest account. Real key material and any particular Cookie do not go into the knowledge base. If a single site misses, do not delete this row from the short table.


## PHP backend Proxy layer has no auth (short-table pointer)

Recognize: a self-built PHP (`action.php?c=X&a=Y` routing) admin backend: admin pages open anonymously without redirecting to login; data goes through `XxxProxy&a=get*List`; the framework has no global session middleware, so the Proxy layer is wide open.

Hit (no login):
1. Open `?c=User`, `?c=Score`, `?c=Role`-style admin pages directly; if a table shell renders, the page layer is open.
2. Extract `XxxProxy&a=get*List` from the inline page JS (GET, `pageNumber/pageSize`, enlarge pageSize and page through) → the whole PII table.
3. For write endpoints (add/update/delete), hit with a **nonexistent object id** as the control: a business validation message ("school id cannot be empty" style) = the write endpoint has no auth; a login redirect / "please log in" = the write endpoint is gated. **Do not touch real data**; create your own test object following "add first → delete your own row".

Counts as: the whole table of names + phones (or scores/roles) comes out directly; write endpoints return a business error rather than a login error.
False positives: the list/write endpoint returns a login redirect; the page opens but the Proxy endpoint needs a session; only public marketing data.

## Empty credentials issue a super-admin session (short-table pointer)

Recognize: the Java backend login endpoint does not verify credential details: empty body / arbitrary loginName+password → `stateCode` 602 "login successful" + **the complete user object (including the password hash)** + Set-Cookie; the same endpoint also has a `vlogin` session verification endpoint.

Hit:
1. POST the login endpoint (parameter names per the frontend login js, commonly `loginName/password`), one shot with an empty password and one with a fake password — both returning 602 means zero credential validation.
2. Use the returned Cookie against `vlogin`: 602 = a real session (the frontend jumps to main on 602).
3. Per the frontend controller, extract `*/list` (**GET**; 405 = already past auth, just the wrong method) to read the account table/employee directory/SMS logs/audit logs; your own login appearing in the audit log = the session is confirmed.
4. If write endpoints (save/resetPwd/delete) are reachable under the session, record it as impact, but **do not actually modify** production data.

Counts as: vlogin 602 + at least one list returning data (account hashes / phones+emails / SMS logs, any one) + audit correlation.
False positives: vlogin returns not-logged-in; list returns a login code; only the user object comes back but the session is not recognised by vlogin (a half chain — do not write it up).

## Interceptor allow-list misses frontend business write endpoints (short-table pointer)

**Shape**: a Spring monolith serving frontend and backend in the same context has a global 302→login interceptor, but it is **allow-list based** (it lets through endpoints used by frontend pages). The frontend allow-list is mixed with real business write endpoints: application submission, refunds, temporary upload, payment query. All view endpoints returning 302 makes it look as if the whole site is gated.

**Technique**:
1. Extract all endpoints from the frontend config/urlSet JS (watch for `httpName+"xxx/yyy"` style without a leading slash).
2. Double-probe every endpoint with GET+POST and empty parameters, classifying by response: `302` = covered by the interceptor; `405` = method mismatch but **already past the interceptor** (thrown during mapping, which does not prove a gate); `500` with a stack trace = anonymous direct reach into the business layer (the stack trace is execution proof and also hands you class names/package names/line numbers).
3. For 500 POST endpoints, assemble full parameters from the frontend JS form fields (sensitive fields may be frontend AES with the key/IV sitting in a hidden page field, statically hard-coded).
4. After a create endpoint succeeds, replay with the returned order number = a write endpoint; a duplicate-key rejection on the same unique key is itself evidence of "can squat and block real users".
5. Record counter-examples: some write endpoints deep-validate a real foreign key (personId must really exist), and empty parameters NPE while progressively faking values still 500s → stop and record honestly "needs a real foreign key".

**Passes the bar**: anonymous persistence produces a business order number, and replaying with that number can rewrite data structures other people can see.
**Does not pass**: the write endpoint returns a login code / SMS code; fully populated parameters still give 411; read-only.

## Verification-code plaintext read-back chain (short-table pointer)

**Shape**: the SMS code system has a "query verification code status" endpoint whose response carries the plaintext yzm besides expire; or the code-sending endpoint returns the code directly. Combined with a code-sending endpoint that has no graphic captcha, the whole code gate collapses.

**Technique**:
1. Send a code with only the phone (your own number) and see whether a captcha/rate limit is in front.
2. Hit the queryYzm-style endpoint: expire=-2 before sending; after sending, expire>0 and yzm=plaintext → hit.
3. Use the code against every *ByPhone gate (queryByPhone/newQueryByPhone/scorebyphone/certuser…); parameter names come from Spring's missing-parameter error (`Required String parameter 'bmrsjhyzm'`), and the body shape follows the frontend axios wrapper (JSON if there is a json header, otherwise qs form).
4. Take the returned entity id to the *ById endpoints (often no code and no auth) to close the evidence loop.
5. Negative control is mandatory: a wrong code/no code must be rejected — proving validation exists and the flaw is the plaintext read-back is what makes the report defensible.

**Passes the bar**: plaintext code read back + pulling your own full application entity (ID number/plaintext phone) or scores with the code.
**Does not pass**: the query endpoint only returns expire; every code endpoint rejects; ByPhone requires a login state.
