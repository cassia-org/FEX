/*
$info$
tags: thunklibs|wayland-client
$end_info$
*/

#include <wayland-util.h>
#include <wayland-client.h>

// These must be re-declared with an initializer here, since they don't get exported otherwise
// NOTE: The initializers for these must be fetched from the host Wayland library, however
//       we can't control how these symbols are loaded since they are global const objects.
//       LD puts them in the application rodata section and ignores any nontrivial library-provided
//       initializers. There is a workaround to enable late initialization anyway in OnInit.
// NOTE: We only need to do this for interfaces exported by libwayland-client itself. Interfaces
//       defined by external libraries work fine.
extern "C" const wl_interface wl_output_interface {};
extern "C" const wl_interface wl_shm_pool_interface {};
extern "C" const wl_interface wl_pointer_interface {};
extern "C" const wl_interface wl_compositor_interface {};
extern "C" const wl_interface wl_shm_interface {};
extern "C" const wl_interface wl_registry_interface {};
extern "C" const wl_interface wl_buffer_interface {};
extern "C" const wl_interface wl_seat_interface {};
extern "C" const wl_interface wl_surface_interface {};
extern "C" const wl_interface wl_keyboard_interface {};
extern "C" const wl_interface wl_callback_interface {};

#include <array>
#include <charconv>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <unordered_map>

#include "common/Guest.h"

#include "thunkgen_guest_libwayland-client.inl"

struct wl_proxy_private {
  wl_interface* interface;
  // Other data members omitted
};

template<char> struct ArgType;
template<> struct ArgType<'s'> { using type = const char*; };
template<> struct ArgType<'u'> { using type = uint32_t; };
template<> struct ArgType<'i'> { using type = int32_t; };
template<> struct ArgType<'o'> { using type = wl_proxy*; };
template<> struct ArgType<'a'> { using type = wl_array*; };
template<> struct ArgType<'f'> { using type = wl_fixed_t; };
template<> struct ArgType<'h'> { using type = int32_t; }; // fd?

template<char... Signature>
static void* WaylandAllocateHostTrampolineForGuestListener(void (*callback)()) {
  using cb = void(void*, wl_proxy*, typename ArgType<Signature>::type...);
  return (void*)AllocateHostTrampolineForGuestFunction((cb*)callback);
}

#define WL_CLOSURE_MAX_ARGS 20

// Per-proxy list of callbacks set up via wl_proxy_add_listener.
// These tables store the host-callable trampolines to the actual listener
// callbacks provided by the guest application.
// NOTE: There can only be one listener per proxy. Wayland will return an error
//       if wl_proxy_add_listener is called twice.
// NOTE: Entries should be removed in wl_destroy_proxy. Since proxy wrappers do
//       not use their own listeners, wl_proxy_wrapper_destroy does not need to
//       be customized.
static std::unordered_map<wl_proxy*, std::array<void*, WL_CLOSURE_MAX_ARGS>> proxy_listeners;

extern "C" int wl_proxy_add_listener(wl_proxy *proxy,
      void (**callback)(void), void *data) {
  auto interface = ((wl_proxy_private*)proxy)->interface;

  // NOTE: This table must remain valid past the return of this function.
  auto& host_callbacks = proxy_listeners[proxy];

  for (int i = 0; i < ((wl_proxy_private*)proxy)->interface->event_count; ++i) {
    auto signature = std::string_view { interface->events[i].signature };

    // A leading number indicates the minimum protocol version
    uint32_t since_version = 0;
    auto [ptr, res] = std::from_chars(signature.begin(), signature.end(), since_version, 10);
    signature = signature.substr(ptr - signature.begin());

    if (signature == "u") {
      // E.g. wl_registry::global_remove
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u'>(callback[i]);
    } else if (signature == "usu") {
      // E.g. wl_registry::global
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 's', 'u'>(callback[i]);
    } else if (signature == "s") {
      // E.g. wl_seat::name
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'s'>(callback[i]);
    } else if (signature == "") {
      // E.g. xdg_toplevel::close
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<>(callback[i]);
    } else if (signature == "ii") {
      // E.g. xdg_toplevel::configure_bounds
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'i', 'i'>(callback[i]);
    } else if (signature == "iia") {
      // E.g. xdg_toplevel::configure
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'i', 'i', 'a'>(callback[i]);
    } else if (signature == "a") {
      // E.g. xdg_toplevel::wm_capabilities
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'a'>(callback[i]);
    } else if (signature == "uoff") {
      // E.g. wl_pointer_listener::enter
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'o', 'f', 'f'>(callback[i]);
    } else if (signature == "uo") {
      // E.g. wl_pointer_listener::leave
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'o'>(callback[i]);
    } else if (signature == "uff") {
      // E.g. wl_pointer_listener::motion
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'f', 'f'>(callback[i]);
    } else if (signature == "uuuu") {
      // E.g. wl_pointer_listener::button
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'u', 'u', 'u'>(callback[i]);
    } else if (signature == "uuf") {
      // E.g. wl_pointer_listener::axis
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'u', 'f'>(callback[i]);
    } else if (signature == "uu") {
      // E.g. wl_pointer_listener::axis_stop
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'u'>(callback[i]);
    } else if (signature == "ui") {
      // E.g. wl_pointer_listener::axis_discrete
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'i'>(callback[i]);
    } else if (signature == "uhu") {
      // E.g. wl_keyboard_listener::keymap
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'h', 'u'>(callback[i]);
    } else if (signature == "uoa") {
      // E.g. wl_keyboard_listener::enter
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'o', 'a'>(callback[i]);
    } else if (signature == "uuuuu") {
      // E.g. wl_keyboard_listener::modifiers
      host_callbacks[i] = WaylandAllocateHostTrampolineForGuestListener<'u', 'u', 'u', 'u', 'u'>(callback[i]);
    } else {
      fprintf(stderr, "Unknown wayland event signature descriptor %s\n", signature.data());
      std::abort();
    }
  }

  return fexfn_pack_wl_proxy_add_listener(proxy, (void(**)())host_callbacks.data(), data);
}

extern "C" void wl_proxy_destroy(struct wl_proxy *proxy) {
  proxy_listeners.erase(proxy);
  return fexfn_pack_wl_proxy_destroy(proxy);
}

// Adapted from the Wayland sources
static const char* get_next_argument_type(const char *signature, char &type)
{
  for (; *signature; ++signature) {
    switch(*signature) {
    case 'i':
    case 'u':
    case 'f':
    case 's':
    case 'o':
    case 'n':
    case 'a':
    case 'h':
      type = *signature;
      return signature + 1;

    default:
      continue;
    }
  }
  type = 0;
  return signature;
}

static void wl_argument_from_va_list(const char *signature, wl_argument *args,
                                     int count, va_list ap) {

  auto sig_iter = signature;
  for (int i = 0; i < count; i++) {
    char arg_type;
    sig_iter = get_next_argument_type(sig_iter, arg_type);

    switch (arg_type) {
    case 'i':
      args[i].i = va_arg(ap, int32_t);
      break;
    case 'u':
      args[i].u = va_arg(ap, uint32_t);
      break;
    case 'f':
      args[i].f = va_arg(ap, wl_fixed_t);
      break;
    case 's':
      args[i].s = va_arg(ap, const char *);
      break;
    case 'o':
      args[i].o = va_arg(ap, struct wl_object *);
      break;
    case 'n':
      args[i].o = va_arg(ap, struct wl_object *);
      break;
    case 'a':
      args[i].a = va_arg(ap, struct wl_array *);
      break;
    case 'h':
      args[i].h = va_arg(ap, int32_t);
      break;
    case '\0':
      return;
    }
  }
}

extern "C" wl_proxy *wl_proxy_marshal_flags(wl_proxy *proxy, uint32_t opcode,
           const wl_interface *interface,
           uint32_t version,
           uint32_t flags, ...) {
  wl_argument args[WL_CLOSURE_MAX_ARGS];
  va_list ap;

  va_start(ap, flags);
#ifdef IS_32BIT_THUNK
// Must extract signature from host due to different data layout on 32-bit
#error Not implemented
#else
  wl_argument_from_va_list(((wl_proxy_private*)proxy)->interface->methods[opcode].signature,
                           args, WL_CLOSURE_MAX_ARGS, ap);
#endif
  va_end(ap);

  // wl_proxy_marshal_array_flags is only available starting from Wayland 1.19.91
#if WAYLAND_VERSION_MAJOR * 10000 + WAYLAND_VERSION_MINOR * 100 + WAYLAND_VERSION_MICRO >= 11991
  return wl_proxy_marshal_array_flags(proxy, opcode, interface, version, flags, args);
#else
  fprintf(stderr, "Host Wayland version is too old to support FEX thunking\n");
  __builtin_trap();
#endif
}

void OnInit() {
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_output_interface), "wl_output");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_shm_pool_interface), "wl_shm_pool");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_pointer_interface), "wl_pointer");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_compositor_interface), "wl_compositor");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_shm_interface), "wl_shm");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_registry_interface), "wl_registry");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_buffer_interface), "wl_buffer");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_seat_interface), "wl_seat");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_surface_interface), "wl_surface");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_keyboard_interface), "wl_keyboard");
  fex_wl_exchange_interface_pointer(const_cast<wl_interface*>(&wl_callback_interface), "wl_callback");
}

LOAD_LIB_INIT(libwayland-client, OnInit)
