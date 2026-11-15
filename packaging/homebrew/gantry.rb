# Homebrew formula for the gantry CLI, for the tap eliransu/homebrew-tap (brew install eliransu/tap/gantry).
# A template: the release workflow fills the @...@ fields with packaging/homebrew/render.sh and pushes the result to
# the tap as Formula/gantry.rb. Do not edit the tap's copy by hand.
class Gantry < Formula
  desc "Open source AI gateway built for governance"
  homepage "https://gantry.eliran.me"
  version "@VERSION@"
  # The binary is the single Gantry build: Apache-2.0 crates plus enterprise/ under its own license, which stays off
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
    bin.install "gantry"
  end

  def caveats
    "Start the gateway with: gantry start"
  end

  test do
    assert_match "gantry #{version}", shell_output("#{bin}/gantry version")
  end
end
