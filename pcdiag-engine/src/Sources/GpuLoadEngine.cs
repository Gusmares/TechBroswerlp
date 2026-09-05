using System;
using System.Runtime.InteropServices;

namespace PcDiag.Sources
{
    // ================================================================
    //  Motor de carga real de GPU: janela minima (fora da area visivel) +
    //  contexto OpenGL 1.1 de funcao fixa, desenhando varias camadas de
    //  overdraw texturizado com blending alfa. Isso ocupa unidades de
    //  textura, ROPs e banda de memoria da GPU de forma sustentada -
    //  funciona em qualquer GPU com driver OpenGL (todo Windows tem pelo
    //  menos o renderizador de software da Microsoft), sem depender de
    //  CUDA/OpenCL/DirectX SDK.
    //
    //  Mesma filosofia do LowLevelEngine (ver LowLevel.cs): TryCreate NUNCA
    //  lanca. Qualquer falha (sessao sem GPU/RDP basico, driver ausente,
    //  pixel format indisponivel) devolve null com motivo, e a fase de
    //  carga degrada para "nao testado" - nunca finge que a carga rodou.
    //
    //  Cuidado central: em GPU hibrida (notebook com integrada+dedicada) ou
    //  sessao remota, o contexto pode cair no renderizador de SOFTWARE da
    //  Microsoft ("GDI Generic") em vez de qualquer GPU real. Uma carga em
    //  software nao aquece hardware nenhum, e reportar isso como "GPU
    //  testada" seria uma aprovacao vazia - HardwareAccelerated detecta
    //  esse caso lendo GL_VENDOR/GL_RENDERER, para que o chamador nunca
    //  trate essa carga como prova de nada sobre a placa de video real.
    //
    //  Requisito do Win32/WGL: a janela e o contexto so podem ser criados
    //  e usados pela MESMA thread (loop de mensagens e contexto GL sao
    //  afins a thread). Quem usa esta classe precisa criar, renderizar e
    //  descartar tudo na mesma thread dedicada.
    // ================================================================
    public sealed class GpuLoadEngine : IDisposable
    {
        private const int TextureSize = 512;
        private const int LayersPerFrame = 40;
        private const int WindowSize = 64;

        private const uint WS_POPUP = 0x80000000;
        private const int SW_SHOWNOACTIVATE = 4;
        private const int ERROR_CLASS_ALREADY_EXISTS = 1410;

        private const uint WM_DESTROY = 0x0002;
        private const uint WM_CLOSE = 0x0010;
        private const uint WM_QUIT = 0x0012;
        private const uint PM_REMOVE = 0x0001;

        private const uint PFD_DRAW_TO_WINDOW = 0x00000004;
        private const uint PFD_SUPPORT_OPENGL = 0x00000020;
        private const uint PFD_DOUBLEBUFFER = 0x00000001;
        private const byte PFD_TYPE_RGBA = 0;
        private const byte PFD_MAIN_PLANE = 0;

        private const uint GL_COLOR_BUFFER_BIT = 0x00004000;
        private const uint GL_TEXTURE_2D = 0x0DE1;
        private const uint GL_BLEND = 0x0BE2;
        private const uint GL_SRC_ALPHA = 0x0302;
        private const uint GL_ONE_MINUS_SRC_ALPHA = 0x0303;
        private const uint GL_PROJECTION = 0x1701;
        private const uint GL_MODELVIEW = 0x1700;
        private const uint GL_RGBA = 0x1908;
        private const uint GL_UNSIGNED_BYTE = 0x1401;
        private const uint GL_TEXTURE_MIN_FILTER = 0x2801;
        private const uint GL_TEXTURE_MAG_FILTER = 0x2800;
        private const uint GL_LINEAR = 0x2601;
        private const uint GL_QUADS = 0x0007;
        private const uint GL_VENDOR = 0x1F00;
        private const uint GL_RENDERER = 0x1F01;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct WNDCLASS
        {
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszMenuName;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszClassName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int x; public int y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PIXELFORMATDESCRIPTOR
        {
            public ushort nSize;
            public ushort nVersion;
            public uint dwFlags;
            public byte iPixelType;
            public byte cColorBits;
            public byte cRedBits, cRedShift, cGreenBits, cGreenShift, cBlueBits, cBlueShift;
            public byte cAlphaBits, cAlphaShift;
            public byte cAccumBits, cAccumRedBits, cAccumGreenBits, cAccumBlueBits, cAccumAlphaBits;
            public byte cDepthBits;
            public byte cStencilBits;
            public byte cAuxBuffers;
            public byte iLayerType;
            public byte bReserved;
            public uint dwLayerMask;
            public uint dwVisibleMask;
            public uint dwDamageMask;
        }

        private delegate IntPtr WndProcDelegate(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool WglSwapIntervalFn(int interval);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandleA(string lpModuleName);

        [DllImport("user32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern ushort RegisterClassA(ref WNDCLASS lpWndClass);

        [DllImport("user32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr CreateWindowExA(uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll")]
        private static extern IntPtr DefWindowProcA(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        private static extern bool PeekMessageA(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessageA(ref MSG lpMsg);

        [DllImport("user32.dll")]
        private static extern void PostQuitMessage(int nExitCode);

        [DllImport("gdi32.dll")]
        private static extern int ChoosePixelFormat(IntPtr hdc, ref PIXELFORMATDESCRIPTOR ppfd);

        [DllImport("gdi32.dll")]
        private static extern bool SetPixelFormat(IntPtr hdc, int format, ref PIXELFORMATDESCRIPTOR ppfd);

        [DllImport("gdi32.dll")]
        private static extern bool SwapBuffers(IntPtr hdc);

        [DllImport("opengl32.dll")]
        private static extern IntPtr wglCreateContext(IntPtr hdc);

        [DllImport("opengl32.dll")]
        private static extern bool wglMakeCurrent(IntPtr hdc, IntPtr hglrc);

        [DllImport("opengl32.dll")]
        private static extern bool wglDeleteContext(IntPtr hglrc);

        [DllImport("opengl32.dll")]
        private static extern IntPtr wglGetProcAddress(string name);

        [DllImport("opengl32.dll")]
        private static extern IntPtr glGetString(uint name);

        [DllImport("opengl32.dll")]
        private static extern void glClear(uint mask);

        [DllImport("opengl32.dll")]
        private static extern void glEnable(uint cap);

        [DllImport("opengl32.dll")]
        private static extern void glBlendFunc(uint sfactor, uint dfactor);

        [DllImport("opengl32.dll")]
        private static extern void glViewport(int x, int y, int width, int height);

        [DllImport("opengl32.dll")]
        private static extern void glMatrixMode(uint mode);

        [DllImport("opengl32.dll")]
        private static extern void glLoadIdentity();

        [DllImport("opengl32.dll")]
        private static extern void glOrtho(double left, double right, double bottom, double top, double zNear, double zFar);

        [DllImport("opengl32.dll")]
        private static extern void glGenTextures(int n, out uint textures);

        [DllImport("opengl32.dll")]
        private static extern void glBindTexture(uint target, uint texture);

        [DllImport("opengl32.dll")]
        private static extern void glTexParameteri(uint target, uint pname, int param);

        [DllImport("opengl32.dll")]
        private static extern void glTexImage2D(uint target, int level, int internalFormat, int width, int height,
            int border, uint format, uint type, IntPtr pixels);

        [DllImport("opengl32.dll")]
        private static extern void glBegin(uint mode);

        [DllImport("opengl32.dll")]
        private static extern void glEnd();

        [DllImport("opengl32.dll")]
        private static extern void glVertex2f(float x, float y);

        [DllImport("opengl32.dll")]
        private static extern void glTexCoord2f(float s, float t);

        [DllImport("opengl32.dll")]
        private static extern void glColor4f(float r, float g, float b, float a);

        // Mantida como campo: se o delegate fosse so uma variavel local, o
        // coletor de lixo poderia liberar o thunk nativo enquanto o Windows
        // ainda guarda o ponteiro registrado em WNDCLASS.lpfnWndProc.
        private readonly WndProcDelegate _wndProcDelegate;

        private IntPtr _hInstance;
        private IntPtr _hwnd;
        private IntPtr _hdc;
        private IntPtr _hglrc;
        private double _frameT;
        private volatile bool _closed;

        public string RenderVendor { get; private set; }
        public string RenderDevice { get; private set; }
        public bool HardwareAccelerated { get; private set; }

        private GpuLoadEngine()
        {
            _wndProcDelegate = WndProc;
        }

        public static GpuLoadEngine TryCreate(out string unavailableReason)
        {
            unavailableReason = null;
            GpuLoadEngine engine = new GpuLoadEngine();
            try
            {
                engine.Build();
                return engine;
            }
            catch (Exception ex)
            {
                engine.Dispose();
                unavailableReason = ex.GetType().Name + ": " + ex.Message;
                return null;
            }
        }

        private void Build()
        {
            _hInstance = GetModuleHandleA(null);

            WNDCLASS wc = new WNDCLASS();
            wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProcDelegate);
            wc.hInstance = _hInstance;
            wc.lpszClassName = "PcDiagGpuLoad";

            if (RegisterClassA(ref wc) == 0)
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_CLASS_ALREADY_EXISTS)
                    throw new InvalidOperationException("RegisterClassA falhou (erro " + err + ").");
            }

            // Fora da area visivel de qualquer monitor real: a carga nao
            // precisa aparecer para o tecnico, so precisa de um HDC valido
            // para o driver aceitar um contexto OpenGL.
            _hwnd = CreateWindowExA(0, "PcDiagGpuLoad", "PcDiag - carga de GPU", WS_POPUP,
                -32000, -32000, WindowSize, WindowSize, IntPtr.Zero, IntPtr.Zero, _hInstance, IntPtr.Zero);
            if (_hwnd == IntPtr.Zero)
                throw new InvalidOperationException("CreateWindowExA falhou (erro " + Marshal.GetLastWin32Error() + ").");

            ShowWindow(_hwnd, SW_SHOWNOACTIVATE);

            _hdc = GetDC(_hwnd);
            if (_hdc == IntPtr.Zero) throw new InvalidOperationException("GetDC devolveu nulo.");

            PIXELFORMATDESCRIPTOR pfd = new PIXELFORMATDESCRIPTOR();
            pfd.nSize = (ushort)Marshal.SizeOf(typeof(PIXELFORMATDESCRIPTOR));
            pfd.nVersion = 1;
            pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
            pfd.iPixelType = PFD_TYPE_RGBA;
            pfd.cColorBits = 32;
            pfd.iLayerType = PFD_MAIN_PLANE;

            int format = ChoosePixelFormat(_hdc, ref pfd);
            if (format == 0)
                throw new InvalidOperationException("ChoosePixelFormat nao encontrou formato compativel - driver de video sem suporte a OpenGL.");
            if (!SetPixelFormat(_hdc, format, ref pfd))
                throw new InvalidOperationException("SetPixelFormat falhou (erro " + Marshal.GetLastWin32Error() + ").");

            _hglrc = wglCreateContext(_hdc);
            if (_hglrc == IntPtr.Zero)
                throw new InvalidOperationException("wglCreateContext falhou - sem contexto OpenGL disponivel nesta sessao.");
            if (!wglMakeCurrent(_hdc, _hglrc))
                throw new InvalidOperationException("wglMakeCurrent falhou.");

            RenderVendor = ReadGlString(GL_VENDOR);
            RenderDevice = ReadGlString(GL_RENDERER);
            HardwareAccelerated = ClassifyHardwareAccelerated(RenderVendor, RenderDevice);

            TryDisableVsync();
            SetupScene();
        }

        // Notebook com GPU hibrida pode entregar o contexto na GPU
        // INTEGRADA sem que o driver acuse erro nenhum - isso ainda conta
        // como aceleracao de hardware real (o silicio grafico aquece de
        // verdade), so nao necessariamente o mesmo chip que GpuCollector
        // classificou como "Dedicada". O unico caso a rejeitar e o
        // renderizador de SOFTWARE da Microsoft, que nao usa GPU nenhuma -
        // uma carga nele nao prova nada sobre a placa de video real.
        private static bool ClassifyHardwareAccelerated(string vendor, string renderer)
        {
            if (string.IsNullOrEmpty(vendor)) return false;
            if (vendor.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (!string.IsNullOrEmpty(renderer) && renderer.IndexOf("GDI Generic", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            return true;
        }

        private static string ReadGlString(uint name)
        {
            IntPtr ptr = glGetString(name);
            return ptr == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(ptr);
        }

        private void TryDisableVsync()
        {
            IntPtr proc = wglGetProcAddress("wglSwapIntervalEXT");
            if (proc == IntPtr.Zero) return;
            try
            {
                WglSwapIntervalFn fn = (WglSwapIntervalFn)Marshal.GetDelegateForFunctionPointer(proc, typeof(WglSwapIntervalFn));
                fn(0);
            }
            catch { /* vsync so limitaria a carga ao Hz do monitor - opcional */ }
        }

        private void SetupScene()
        {
            IntPtr texData = BuildProceduralTexture(TextureSize);
            try
            {
                uint texture;
                glGenTextures(1, out texture);
                glBindTexture(GL_TEXTURE_2D, texture);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, (int)GL_LINEAR);
                glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, (int)GL_LINEAR);
                glTexImage2D(GL_TEXTURE_2D, 0, (int)GL_RGBA, TextureSize, TextureSize, 0, GL_RGBA, GL_UNSIGNED_BYTE, texData);
            }
            finally
            {
                Marshal.FreeHGlobal(texData);
            }

            glEnable(GL_TEXTURE_2D);
            glEnable(GL_BLEND);
            glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
            glViewport(0, 0, WindowSize, WindowSize);
            glMatrixMode(GL_PROJECTION);
            glLoadIdentity();
            glOrtho(0, 1, 0, 1, -1, 1);
            glMatrixMode(GL_MODELVIEW);
        }

        private static IntPtr BuildProceduralTexture(int size)
        {
            byte[] pixels = new byte[size * size * 4];
            for (int y = 0; y < size; y++)
            {
                for (int x = 0; x < size; x++)
                {
                    int i = (y * size + x) * 4;
                    pixels[i + 0] = (byte)((x * 255) / size);
                    pixels[i + 1] = (byte)((y * 255) / size);
                    pixels[i + 2] = (byte)(((x ^ y) * 255) / size);
                    pixels[i + 3] = 200;
                }
            }

            IntPtr buffer = Marshal.AllocHGlobal(pixels.Length);
            Marshal.Copy(pixels, 0, buffer, pixels.Length);
            return buffer;
        }

        // Chamado em loop pela thread dona da janela. Desenha varias
        // camadas sobrepostas com blending para gerar carga real e sustentada
        // de textura/ROP/banda de memoria de video.
        public void RenderFrame()
        {
            glClear(GL_COLOR_BUFFER_BIT);
            for (int c = 0; c < LayersPerFrame; c++)
            {
                float offset = (float)(0.02 * Math.Sin(_frameT * 0.7 + c));
                float alpha = 0.04f + 0.02f * (float)Math.Cos(_frameT + c);
                glColor4f(1.0f, 1.0f, 1.0f, alpha);
                glBegin(GL_QUADS);
                glTexCoord2f(0.0f + offset, 0.0f); glVertex2f(0.0f, 0.0f);
                glTexCoord2f(3.0f + offset, 0.0f); glVertex2f(1.0f, 0.0f);
                glTexCoord2f(3.0f + offset, 3.0f); glVertex2f(1.0f, 1.0f);
                glTexCoord2f(0.0f + offset, 3.0f); glVertex2f(0.0f, 1.0f);
                glEnd();
            }
            SwapBuffers(_hdc);
            _frameT += 0.01;
        }

        // Esvazia a fila de mensagens da janela. Precisa ser chamado
        // periodicamente pela mesma thread dona da janela, senao o Windows
        // considera a janela "nao respondendo". Devolve false quando a
        // janela foi fechada (WM_CLOSE/WM_DESTROY/WM_QUIT) - sinal para o
        // chamador encerrar o loop de renderizacao.
        public bool PumpMessages()
        {
            MSG msg;
            while (PeekMessageA(out msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                TranslateMessage(ref msg);
                DispatchMessageA(ref msg);
                if (msg.message == WM_QUIT) return false;
            }
            return !_closed;
        }

        private IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            if (msg == WM_CLOSE || msg == WM_DESTROY)
            {
                _closed = true;
                PostQuitMessage(0);
                return IntPtr.Zero;
            }
            return DefWindowProcA(hwnd, msg, wParam, lParam);
        }

        // Precisa ser chamado pela MESMA thread que criou a janela/contexto
        // (regra do WGL) - quem usa esta classe garante isso rodando tudo
        // dentro de uma unica thread dedicada, do TryCreate ate o Dispose.
        public void Dispose()
        {
            if (_hglrc != IntPtr.Zero)
            {
                wglMakeCurrent(IntPtr.Zero, IntPtr.Zero);
                wglDeleteContext(_hglrc);
                _hglrc = IntPtr.Zero;
            }
            if (_hdc != IntPtr.Zero && _hwnd != IntPtr.Zero)
            {
                ReleaseDC(_hwnd, _hdc);
                _hdc = IntPtr.Zero;
            }
            if (_hwnd != IntPtr.Zero)
            {
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
            }
        }
    }
}
