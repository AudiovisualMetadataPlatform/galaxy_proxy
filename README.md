# galaxy_proxy

---
PROOF OF CONCEPT -- DO NOT USE IN PRODUCTION

---


This is a proof-of-concept proxy to allow the galaxy workflow editor to be limited so it doesn't allow unauthorized access to the galaxy backend.

I slapped it together in about 45 minutes so there are a lot of things it doesn't do that would be required to make sure it would work in a production setting:
* communicate with AMP to validate an AMP session cookie
* validate that the AMP user is currently editing a workflow and which one
* validate the URL is a valid call for a user to edit the particular workflow
* log into galaxy and store the galaxy session cookie on the AMP side, or retrieve an existing cookie from the AMP user session.
* catch any galaxysession cookie updates and update the AMP end
* default to deny-all instead of the allow-all as it's currently implemented
* deal with any corner case issues with the http protocol, especially in regards to caching parameters
* better logging and debugging
* performance using the ThreadedHTTPServer class may not be up to par
* I worry a bit about the REST payload size.  Meh, it'll probably be fine.



