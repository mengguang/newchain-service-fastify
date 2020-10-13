// Require the framework and instantiate it
const fastify = require('fastify')({
    logger: true
})
fastify.register(require('fastify-formbody'))
const secp256k1 = require('secp256k1')
const port = 3000

fastify.post('/crypto/ecdsa-recover', async (req, res) => {

    const signature = req.body['signature'];
    if (signature === undefined || signature.length !== 128) {
        res.send({result: "fail", info: "invalid signature"});
        return;
    }
    const message_hash = req.body['message_hash'];
    if (message_hash === undefined || message_hash.length !== 64) {
        res.send({result: "fail", info: "invalid message_hash"});
        return;
    }
    const v = req.body['v'];
    if (v === undefined || parseInt(v) >= 3 || parseInt(v) < 0) {
        res.send({result: "fail", info: "invalid v"});
        return;
    }

    const b_signature = Uint8Array.from(Buffer.from(signature, 'hex'));
    const b_message_hash = Uint8Array.from(Buffer.from(message_hash, 'hex'));
    const i_v = parseInt(v);
    const public_key = new Uint8Array(65);
    try {
        secp256k1.ecdsaRecover(b_signature, i_v, b_message_hash, false, public_key);
    } catch (err) {
        res.send({result: "fail", info: err.message});
        return;
    }

    const hex_public_key = Buffer.from(public_key).toString('hex');
    res.send({result: "success", public_key: hex_public_key.slice(2)});
})

const start = async () => {
    try {
        await fastify.listen(port)
    } catch (err) {
        fastify.log.error(err)
        process.exit(1)
    }
}
start()