import Foundation
import SwiftUI

/// User-interface language. English strings are the keys; `Localizable.strings` in
/// `Resources/<lang>.lproj` supplies the translation (Traditional Chinese today). The choice
/// follows the system language unless the user picks one with the toolbar language picker; the choice is
/// stored in UserDefaults (`ui.language`) and applies immediately without a relaunch.
///
/// Strings that originate in the Rust core (paths, hashes, adapter diagnostics, report text)
/// are shown as produced; the ones with a fixed vocabulary (stage names, gate names, error
/// codes, blockers) are translated here by looking the English text up as a key.
@MainActor
final class LanguageStore: ObservableObject {
    enum Choice: String, CaseIterable, Identifiable {
        case system
        case english = "en"
        case traditionalChinese = "zh-Hant"
        var id: String { rawValue }
    }

    static let shared = LanguageStore()
    static let supported = ["en", "zh-Hant"]
    private static let defaultsKey = "ui.language"

    /// Bundle that carries the `.lproj` directories: the SwiftPM resource bundle when built with
    /// `swift build`, the application bundle when built by Xcode.
    static let resources: Bundle = {
        #if SWIFT_PACKAGE
        return Bundle.module
        #else
        return Bundle.main
        #endif
    }()

    @Published var choice: Choice {
        didSet {
            UserDefaults.standard.set(choice.rawValue, forKey: Self.defaultsKey)
            bundle = Self.resolve(choice)
        }
    }
    @Published private(set) var bundle: Bundle

    private init() {
        let stored = UserDefaults.standard.string(forKey: Self.defaultsKey).flatMap(Choice.init(rawValue:)) ?? .system
        choice = stored
        bundle = Self.resolve(stored)
    }

    /// Language code in effect (`en` or `zh-Hant`).
    var code: String {
        switch choice {
        case .system: return Bundle.preferredLocalizations(from: Self.supported).first ?? "en"
        case .english, .traditionalChinese: return choice.rawValue
        }
    }

    var locale: Locale { Locale(identifier: code) }

    private static func resolve(_ choice: Choice) -> Bundle {
        let code: String
        switch choice {
        case .system: code = Bundle.preferredLocalizations(from: supported).first ?? "en"
        case .english, .traditionalChinese: code = choice.rawValue
        }
        if let path = resources.path(forResource: code, ofType: "lproj"), let b = Bundle(path: path) {
            return b
        }
        return resources
    }

    /// Translate; the key itself (English) is the fallback.
    func t(_ key: String) -> String {
        bundle.localizedString(forKey: key, value: key, table: nil)
    }

    /// Translate a format string and fill it.
    func f(_ key: String, _ args: CVarArg...) -> String {
        String(format: t(key), locale: locale, arguments: args)
    }

    /// Optional translation: nil when no entry exists for the key.
    func optional(_ key: String) -> String? {
        let v = bundle.localizedString(forKey: key, value: "\u{0}", table: nil)
        return v == "\u{0}" ? nil : v
    }

    /// Localized title for a core error code; falls back to the English title from RecoveryKit.
    func errorTitle(code: String, fallback: String) -> String {
        optional("error.\(code).title") ?? t(fallback)
    }

    /// Plain-language explanation for a core error code, when one is written.
    func errorHelp(code: String) -> String? {
        optional("error.\(code).help")
    }

    func name(of choice: Choice) -> String {
        switch choice {
        case .system: return t("System language")
        case .english: return "English"
        case .traditionalChinese: return "繁體中文"
        }
    }
}
