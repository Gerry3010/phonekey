package camera

// Placeholder is the I420 picture the webcam shows while the phone does not
// stream: dark grey with a lighter camera outline in the middle, so a video
// app shows that the webcam is there but idle.
func Placeholder(width, height int) []byte {
	pic := make([]byte, PictureSize(width, height))
	const (
		background = 32
		outline    = 110
	)
	luma := pic[:width*height]
	for i := range luma {
		luma[i] = background
	}
	for i := range pic[width*height:] {
		pic[width*height+i] = 128 // no colour
	}
	// A camera: a body with a lens, drawn as outlines in the luma plane.
	cx, cy := width/2, height/2
	unit := max(height/24, 2)
	stroke := max(unit/3, 1)
	rect := func(x0, y0, x1, y1 int) {
		for y := max(y0, 0); y < min(y1, height); y++ {
			for x := max(x0, 0); x < min(x1, width); x++ {
				inner := x >= x0+stroke && x < x1-stroke && y >= y0+stroke && y < y1-stroke
				if !inner {
					luma[y*width+x] = outline
				}
			}
		}
	}
	rect(cx-4*unit, cy-3*unit, cx+4*unit, cy+3*unit) // body
	rect(cx-2*unit, cy-4*unit, cx, cy-3*unit+stroke) // viewfinder bump
	rect(cx-2*unit, cy-2*unit, cx+2*unit, cy+2*unit) // lens
	return pic
}
