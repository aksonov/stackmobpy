# Overview

This code provides basic support for insert/update/delete operations for StackMob database with usage of their REST API.
OAuth2.0 authorization header is set automatically, if access_token is expired, new access token will be automatically
 retrieved.

* 100% unit test coverage.
* Only standard Python libraries, no third-party dependencies
* Could be run on Google AppEngine

# Usage

    import stackmobpy

    client = StackMobClient(TEST_API_KEY, username=TEST_USER, password=TEST_PASSWORD)

    # delete record if it exists
    if client.select('test', '123'):
        client.delete('test', '123')

    client.insert('test', {'test_id':"123", 'test_name':'TEST_NAME'})

    # read record
    rec = client.select('test', '123')

    # update record
    self.client.update('test', '123', {'test_name': "UPDATED_NAME"})
