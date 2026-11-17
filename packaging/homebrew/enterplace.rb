# Homebrew formula for the enterplace CLI, for the tap eliransu/homebrew-tap (brew install eliransu/tap/enterplace).
# A template: the release workflow fills the @...@ fields with packaging/homebrew/render.sh and pushes the result to
# the tap as Formula/enterplace.rb. Do not edit the tap's copy by hand.
class Enterplace < Formula
  desc "Open source AI gateway built for governance"
  homepage "https://enterplace.dev"
  version "@VERSION@"
  # The binary is the single Enterplace build: Apache-2.0 crates plus enterprise/ under its own license, which stays off
  # without a license key. Both license files are in the tarball.
  license :cannot_represent

  on_macos do
    on_arm do
      url "@URL_aarch64-apple-darwin@"
      sha256 "@SHA_aarch64-apple-darwin@"
    end
    on_intel do
      url "@URL_x86_64-apple-darwin@"
      sha256 "@SHA_x86_64-apple-darwin@"
    end
  end

  on_linux do
    on_arm do
      url "@URL_aarch64-unknown-linux-musl@"
      sha256 "@SHA_aarch64-unknown-linux-musl@"
    end
    on_intel do
      url "@URL_x86_64-unknown-linux-musl@"
      sha256 "@SHA_x86_64-unknown-linux-musl@"
    end
  end

  def install
    bin.install "enterplace"
  end

  def caveats
    "Start the gateway with: enterplace start"
  end

  test do
    assert_match "enterplace #{version}", shell_output("#{bin}/enterplace version")
  end
end
