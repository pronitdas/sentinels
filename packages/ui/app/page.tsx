'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Plus, Shield, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Project {
  id: string;
  name: string;
  path: string;
  created_at: string;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [newProject, setNewProject] = useState({ name: '', path: '' });
  const [isCreating, setIsCreating] = useState(false);

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const res = await fetch(`${API_URL}/projects`);
      const data = await res.json();
      setProjects(data);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
    } finally {
      setLoading(false);
    }
  };

  const createProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API_URL}/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newProject),
      });
      if (res.ok) {
        setNewProject({ name: '', path: '' });
        setIsCreating(false);
        fetchProjects();
      }
    } catch (error) {
      console.error('Failed to create project:', error);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 p-8 font-sans">
      <header className="mb-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-indigo-900">Sentinel</h1>
        </div>
        <button
          onClick={() => setIsCreating(!isCreating)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors shadow-sm"
        >
          <Plus className="w-4 h-4" />
          Add Project
        </button>
      </header>

      <main className="max-w-5xl mx-auto">
        {isCreating && (
          <div className="mb-8 p-6 bg-white rounded-xl shadow-md border border-slate-100 animate-in fade-in slide-in-from-top-4">
            <h2 className="text-lg font-semibold mb-4 text-slate-800">New Project</h2>
            <form onSubmit={createProject} className="flex flex-col md:flex-row gap-4">
              <input
                type="text"
                placeholder="Project Name"
                className="flex-1 px-4 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                value={newProject.name}
                onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                required
              />
              <input
                type="text"
                placeholder="Absolute Host Path (e.g., /home/user/code/repo)"
                className="flex-[2] px-4 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                value={newProject.path}
                onChange={(e) => setNewProject({ ...newProject, path: e.target.value })}
                required
              />
              <button
                type="submit"
                className="px-6 py-2 bg-slate-900 text-white rounded-md hover:bg-slate-800 transition-colors"
              >
                Create
              </button>
            </form>
          </div>
        )}

        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading projects...</div>
        ) : projects.length === 0 ? (
          <div className="text-center py-20 bg-white rounded-xl border border-dashed border-slate-300">
            <Shield className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-700">No projects yet</h3>
            <p className="text-slate-500 max-w-sm mx-auto mt-2">
              Add a local directory to start scanning for security vulnerabilities.
            </p>
          </div>
        ) : (
          <div className="grid gap-4">
            {projects.map((project) => (
              <Link
                key={project.id}
                href={`/projects/${project.id}`}
                className="group block p-6 bg-white rounded-xl border border-slate-200 hover:border-indigo-300 hover:shadow-md transition-all"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-800 group-hover:text-indigo-700 transition-colors">
                      {project.name}
                    </h3>
                    <p className="text-sm text-slate-500 mt-1 font-mono bg-slate-100 px-2 py-0.5 rounded inline-block">
                      {project.path}
                    </p>
                  </div>
                  <ChevronRight className="w-5 h-5 text-slate-400 group-hover:text-indigo-500 transition-colors" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}