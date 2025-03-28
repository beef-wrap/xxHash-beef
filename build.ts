import { type Build } from 'xbuild';

const build: Build = {
    common: {
        project: 'xxHash',
        archs: ['x64'],
        variables: [],
        copy: {},
        defines: [],
        options: [
            ['BUILD_SHARED_LIBS', false]
        ],
        subdirectories: ['xxHash/cmake_unofficial'],
        libraries: {
            xxhash: {}
        },
        buildDir: 'build',
        buildOutDir: '../libs',
        buildFlags: []
    },
    platforms: {
        win32: {
            windows: {},
            android: {
                archs: ['x86', 'x86_64', 'armeabi-v7a', 'arm64-v8a'],
            }
        },
        linux: {
            linux: {}
        },
        darwin: {
            macos: {}
        }
    }
}

export default build;