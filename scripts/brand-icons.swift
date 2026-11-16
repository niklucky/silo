// Draws app icons for scripts/brand-icons.sh. Usage:
//   swift icons.swift tile <src.png> <out.png> <canvas> <inset> <radius>
//     src scaled into a rounded square inset from a transparent canvas
//   swift icons.swift sign <sign.png> <out.png> <canvas> <inset> <radius> <signWidthFraction>
//     the flat sign centered on a near-black rounded square
import AppKit
import CoreGraphics

let a = CommandLine.arguments
func load(_ path: String) -> CGImage {
    let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil)!
    return CGImageSourceCreateImageAtIndex(src, 0, nil)!
}
func save(_ ctx: CGContext, _ path: String) {
    let image = ctx.makeImage()!
    let dest = CGImageDestinationCreateWithURL(URL(fileURLWithPath: path) as CFURL, "public.png" as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    CGImageDestinationFinalize(dest)
}

let mode = a[1], out = a[3]
let canvas = Int(a[4])!, inset = CGFloat(Double(a[5])!), radius = CGFloat(Double(a[6])!)
let ctx = CGContext(data: nil, width: canvas, height: canvas, bitsPerComponent: 8, bytesPerRow: 0,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.interpolationQuality = .high
let c = CGFloat(canvas)
let body = CGRect(x: inset, y: inset, width: c - 2 * inset, height: c - 2 * inset)
ctx.addPath(CGPath(roundedRect: body, cornerWidth: radius, cornerHeight: radius, transform: nil))
ctx.clip()

if mode == "tile" {
    ctx.draw(load(a[2]), in: body)
} else {
    ctx.setFillColor(CGColor(srgbRed: 0.031, green: 0.031, blue: 0.031, alpha: 1))
    ctx.fill(body)
    let sign = load(a[2])
    let w = body.width * CGFloat(Double(a[7])!)
    let h = w * CGFloat(sign.height) / CGFloat(sign.width)
    ctx.draw(sign, in: CGRect(x: (c - w) / 2, y: (c - h) / 2, width: w, height: h))
}
save(ctx, out)
