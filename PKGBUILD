# Maintainer: 5amu <v.casalino@protonmail.com>
pkgname=dnshunter
pkgver=1
pkgrel=1
pkgdesc="Make DNS and BGP assessment easier. Just a script to perform many DNS checks automatically."
arch=( 'any' )
url="https://github.com/5amu/dnshunter"
license=('GPL')
depends=( 'whois' 'bind' )
source=( "${pkgname}.sh" )
noextract=( "${pkgname}.sh" )
md5sums=( 'SKIP' )

package() {
    install -Dm755 ${pkgname}.sh ${pkgdir}/usr/bin/${pkgname}
}
