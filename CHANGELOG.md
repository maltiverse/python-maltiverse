# Changelog

## 1.2.10
- Rename the admin `index_scope` literal value from `sandbox` to `showroom`.

## 1.2.9
- Adds support for the new optional IOC PUT query parameter enqueue_ingestion across the Python client.

## 1.2.8
- Add a short PUT timeout to avoid long stalls during bulk uploads when backend failures occur.

## 1.2.7
- Fix: Send admin-only index_scope as query params for PUT requests.

## 1.2.6
- Fix user fields when using auth_tokens instead of login()

## 1.2.5
- Add admin-only index_scope handling to PUT payloads.

## 1.2.4
- Add support for email addresses.
- Fix return typo.
- Update project owners.

## 1.2.2
- Add feed_metadata_get() and feed_download().
- Improve parameter validation and other refactors.

## 1.2.1
- Support sha1 and sha512 algorithms in sample get wrapper.
- Fix missing sample argument in sample_get callable.
