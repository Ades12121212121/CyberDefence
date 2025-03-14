import PyInstaller.__main__
import os

def build_exe():
    main_script = os.path.join(os.getcwd(), 'src', 'main.py')
    
    args = [
        main_script,
        '--name=CyberDefence',
        '--onefile',
        # Removed --noconsole to show CMD window
        '--add-data=src/*.py;src',
        '--add-data=config;config',
        '--hidden-import=tkinter',
        '--hidden-import=queue',
        '--hidden-import=threading',
        '--hidden-import=json',
        '--clean',
        '--workpath=build',
        '--distpath=dist'
    ]
    
    PyInstaller.__main__.run(args)

if __name__ == "__main__":
    build_exe()