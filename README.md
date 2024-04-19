# Firebase Cloud Messaging (FCM) Decryption Library

## Overview

The Firebase Cloud Messaging (FCM) Decryption Library is a Rust library designed to provide functionality for decrypting Firebase Cloud Messaging (FCM) messages within Dart or Flutter projects. FCM is a popular cross-platform messaging solution provided by Firebase, enabling developers to send messages and notifications to their users across various platforms.

## Purpose

This library addresses the need for decrypting FCM messages encrypted with the default encryption scheme used by Firebase within Dart or Flutter applications. While Firebase provides robust encryption mechanisms for securing messages, there are scenarios where developers may need to decrypt these messages within their Dart or Flutter projects.

The Firebase Cloud Messaging (FCM) Decryption Library aims to simplify the process of decrypting FCM messages, allowing developers to seamlessly integrate this functionality into their Dart or Flutter projects by providing a C library that can be used within Rust.

## Key Features

- **Decryption Functionality:** Decrypt FCM messages encrypted with the default encryption scheme used by Firebase.
- **C Library:** Provides a C library that can be used within Dart or Flutter projects for decrypting FCM messages, enabling interoperability between Rust and Dart/Flutter.
- **Platform Compatibility:** Supports integration with Dart or Flutter projects, ensuring compatibility across various platforms.

## Contributing

Contributions to the Firebase Cloud Messaging (FCM) Decryption Library are welcome! If you encounter any bugs, have suggestions for improvements, or would like to contribute new features, please feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

I would like to extend my gratitude to the following individuals for inspiring this project:

- [Matthieu Lemoine](https://github.com/MatthieuLemoine/electron-push-receiver): For providing the initial idea and inspiration for Firebase Cloud Messaging (FCM) integration.
- [RandomEngy](https://github.com/RandomEngy/fcm-push-listener): For developing the FCM Push Listener library in Rust, which served as the foundation for implementing FCM decryption locally.

Their work has been instrumental in inspiring the development of this library, enabling me to provide a robust solution for decrypting FCM messages within Rust projects. I am grateful for their contributions and the open-source community's collaborative spirit.
