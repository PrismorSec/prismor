# Homebrew formula for PrismorSec/homebrew-tap. The release workflow rewrites
# `url` and `sha256` from the PyPI sdist and pushes this file to the tap; edit
# the template here, never the copy in the tap.
#
#   brew install prismorsec/tap/prismor
class Prismor < Formula
  include Language::Python::Virtualenv

  desc "Runtime security and control plane for AI coding agents"
  homepage "https://prismor.dev"
  url "https://files.pythonhosted.org/packages/f9/e4/92a9a0492160626edaa7919785791734065eb798e00f8cd3710ecc26e660/prismor-1.72.5.tar.gz"
  sha256 "ca2f370427dfe6255468a7f239ad746728da8a1153132773bbc07dbe0ea92839"
  license "Apache-2.0"

  # Homebrew's bottled cryptography, so an install never builds it with Rust.
  # The venv sees it through system site-packages (virtualenv_create's default).
  depends_on "cryptography"
  depends_on "libyaml"
  depends_on "python@3.14"

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz"
    sha256 "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      Wire Prismor into your agents:
        prismor setup
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/prismor --version")
  end
end
