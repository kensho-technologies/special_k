# Why Use special_k?

## Unified API for Any Type of Machine Learning Model
Different machine learning tools are often optimized for different purposes,
meaning that a high-performing model might mix and match tools for tasks like preprocessing, prediction, and postprocessing.
For example, a text classifier model might use a TFIDF embedding to preprocess input text,
and a Keras classifier to make binary predictions on the processed embeddings.
These components may not be able to be serialized in the same way.
Within an organization, as well, different groups might work with different machine learning libraries.
Using a single API for loading and saving all models means that serialized models can easily be shared among engineers,
and safely loading a model from a file is as simple as `load_model_from_tarball(path_to_tarfile)`.

## Protection Against Malicious Code Injection
Pickle and any serializers that use it have well-documented [security concerns](https://docs.python.org/3/library/pickle.html#module-pickle).
Namely, pickle should never be used to deserialize untrusted input,
as it is fairly trivial to construct malicious inputs which can execute arbitrary code during deserialization.
Other serialization libraries are not necessarily any safer;
they face the tradeoff between restricting allowable inputs and allowing arbitrary code to be deserialized.
In addition, many serialization libraries are written in C or similar languages for performance reasons,
creating the possibility of attacks that exploit bugs related to memory allocation/deallocation.
`special_k` uses GPG signatures to verify the trustworthiness of any input files,
ensuring that untrusted input is never deserialized.

## Ensuring Statistical Safety
While `special_k` contains cryptographic checks ensuring that every byte being deserialized
has not changed since serialization, it's still possible that a model will not perform as expected
after being deserialized. Why? The environment the model is loaded into is not necessarily the same as the one
that was used to save it. For example, a machine loading a model might be using a different library version
of some dependency than the machine that saved the model. If this version of the library contains behavioral changes,
the exact same code may not be able to run anymore.
Even more insidiously, changes in floating-point arithmetic operations on model weights or parameters
(e.g. a different value for the [ffast-math flag](https://gcc.gnu.org/wiki/FloatingPointMath) in the C compiler gcc)
could lead to drastic changes in model output.
This kind of error is both serious and difficult to observe.

"Statistical safety" is the assurance that a deserialized model will perform as it did before serialization.
While we can't guarantee statistical safety, `special_k` increases our confidence
in the statistical safety of a model by running model-specific validation code post-deserialization.
These validation checks generally involve serializing a small amount of sample input data along with the model,
along with the model's predictions on this input,
and checking that predictions post-deserialization on these inputs exactly match the expected outputs.
With a small, but non-trivial, set of input data, we can achieve a high degree of confidence that the model will perform as expected.

## Additional Design Features
- Signing is built on PGP and can make use of the full functionality of its trust model. 

- It is very easy to de-serialize models. This comes at the cost of slightly increased 
complexity in serializing a model. It is therefore very difficult to break and very
easy to use a model once it has been properly serialized. 

- Models fail quickly on deserialization. It is difficult (but not impossible) to get to 
the end of reading/writing a large model only to error at the end. All possible checks
are done up front in order to fail fast.  

# How Does special_k Work?
Our model serialization API uses cryptographic verification of models to prevent deserialization of malicious files.
Each attribute of a model is serialized individually, using the designated serializer for that attribute.
Each attribute is then replaced with a sentinel value (so the attribute is not pickled),
and then the model itself (the code gluing the attributes together) is pickled.
The data for each object being serialized is written to an object called a [VerifiableStream](../special_k/verifiable_stream.py),
after which the stream is “finalized”, disabling further writes and enabling reads.
The VerifiableStream calculates the HMAC hashes of the data,
and the hash of each serialized attribute is saved in a metadata file that is serialized along with the models.
To ensure that these hashes themselves can be trusted, a GPG keypair is used to sign the metadata.
Because the metadata is signed before being written to a file, even an attacker that has (non-root) access to the
machine serializing models would not be able to tamper with the model before the metadata is signed!

During deserialization, this process happens in reverse.
Trusted GPG keys are used to validate the signature on the model metadata, ensuring that the metadata file has not been changed.
The HMAC hashes of each serialized model attribute are then calculated and compared to the hashes present in the metadata file.
Since the metadata is guaranteed to not have changed, if these hashes match those present in the metadata,
we can be sure that none of the attributes have been changed either.
Therefore, the model is safe to deserialize!
The model is then unpickled, the sentinel values replacing model attributes are verified,
and then each attribute is deserialized using the appropriate serializer for that attribute.
Finally, user-provided validation code is run once the model has been pieced back together.


# Usage of special_k in Practice
## Automated Model Training and Storage
`special_k` makes deserialization very simple at the expense of a slightly more involved serialization process.
Therefore, we almost exclusively use a centralized, automated piece of software for training, signing and serializing models.
This software's public GPG key can then be easily used by any engineer to verify and load serialized models.
This strategy is less complex than having individual engineers serialize models with their own private keys
and trusting each other's keys for deserialization.

## Public Key Management
To make it easier to work with projects that load models, public keys can be kept in a directory in version control,
and the environment variable SERIALIZATION_TRUSTED_KEYS_DIR can be pointed to this directory.
The downside of this approach is that when keys expire or have to be changed, a code change is required.
A better approach may be to keep public keys in easily accessible configuration files.
