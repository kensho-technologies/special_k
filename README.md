# Special K
A library for safe cereal-ization of machine learning models.

The proliferation of machine learning tools and frameworks has made it easy to build models optimized for many different purposes.
However, when seemingly every machine learning framework has a different means of serializing models,
saving and loading models can get tricky.
Even a single model might contain components that can't be serialized in the same way.

The first approach people might consider to serialize and deserialize Python objects is to use pickle,
the default Python serializer. However, there are three main problems with this approach:

1. Not all Python objects are picklable, including many of the objects often used in ML models.
2. Pickle and other serialization libraries are not recommended for use with untrusted inputs,
since deserializing a malicious payload could lead to malicious code execution.
3. Even if our model is able to be successfully pickled and unpickled,
it still may not work as expected after being loaded
if the environment it's loaded into is different from the one in which it was serialized.

`special_k` provides a consistent API for loading and saving models,
regardless of what attributes the model has or how those attributes are serialized.
It safeguards against arbitrary code injection during deserialization
by cryptographically validating that every single byte of the model is the same as it was when it was serialized.
Lastly, it automatically runs user-provided validation code after deserialization to ensure that the model functions as expected.

[About](./docs/overview.md)
- [Why Use special_k?](./docs/overview.md#why-use-special-k)
- [How Does special_k Work?](./docs/overview.md#how-does-special-k-work)
- [Usage of special_k in Practice](./docs/overview.md#usage-of-special-k-in-practice)

[Getting Started](./docs/getting_started.md)
- [Installation](./docs/getting_started.md#Installation)
- [GPG Setup](./docs/getting_started.md#gpg-setup)

[Usage](./docs/usage.md)
- [Creating a Serializable Model](./docs/usage.md#creating-a-serializable-model)
- [Serializing and Deserializing Models](./docs/usage.md#serializing-and-deserializing-models)

[Advanced Usage](./docs/advanced_usage.md)
- [Registering a Custom Serializer](./docs/advanced_usage.md#registering-a-custom-serializer)
- [Checking GPG Key Expiration](./docs/advanced_usage.md#checking-gpg-key-expiration)

# License

Licensed under the Apache 2.0 License. Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Copyright 2020-present Kensho Technologies, LLC. The present date is determined by the timestamp of the most recent commit in the repository.

