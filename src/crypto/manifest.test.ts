import { test } from "node:test";
import assert from "node:assert/strict";
import { MasterKey, sealEnvelope, verifyManifest } from "../../dist/index.js";

void test("signed manifests authorize an exact envelope and generation", () => {
  const administrator = new MasterKey(Buffer.alloc(32, 7));
  const outsider = new MasterKey(Buffer.alloc(32, 8));
  const recipientPurpose = "repo:1/encryption/v1";
  const signingPurpose = "repo:1/administrator/v1";
  const context = "repo:1/object:config";
  const repositoryId = Buffer.alloc(32, 9);
  const recipient = administrator.encryptionPublicKey(recipientPurpose);
  const envelope = sealEnvelope(context, Buffer.from("secret"), [recipient]);
  const signed = administrator.signManifest(
    signingPurpose,
    repositoryId,
    4n,
    [recipient],
    envelope,
  );
  const administratorPublic = administrator.signingPublicKey(signingPurpose);

  assert.equal(verifyManifest(signed, repositoryId, 4n, [administratorPublic], envelope), true);
  assert.throws(() =>
    verifyManifest(signed, Buffer.alloc(32, 10), 4n, [administratorPublic], envelope),
  );
  assert.throws(() => verifyManifest(signed, repositoryId, 5n, [administratorPublic], envelope));
  assert.throws(() =>
    verifyManifest(signed, repositoryId, 4n, [outsider.signingPublicKey(signingPurpose)], envelope),
  );
  assert.throws(() =>
    verifyManifest(signed, repositoryId, 4n, [administratorPublic], `${envelope} `),
  );
  assert.throws(() =>
    administrator.signManifest(
      signingPurpose,
      repositoryId,
      4n,
      [outsider.encryptionPublicKey(recipientPurpose)],
      envelope,
    ),
  );
});
